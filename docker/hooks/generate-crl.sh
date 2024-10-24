#!/usr/bin/env bash

function generate_crl_secret() {
  issuer_api="$1"
  issues_kind="$2"
  issues_uid="$3"
  issues_name="$4"
  secret_namespace="$5"
  secret_name="$6"
  revoked_certs="$7"
  crl="$8"
  certs_to_renew="$9"

  revoked_certs_base64=$(echo "$revoked_certs" | base64 -w 0)
  crl_base64=$(echo "$crl" | base64 -w 0)

  cat >> $KUBERNETES_PATCH_PATH <<EOF
---
operation: CreateOrUpdate
object:
  apiVersion: v1
  kind: Secret
  metadata:
    name: $secret_name
    namespace: $secret_namespace
    labels:
      cm-crl-generator.citc.dev/track: "true"
    annotations:
      cm-crl-generator.citc.dev/certs-to-renew: "$certs_to_renew"
    ownerReferences:
    - kind: $issues_kind
      apiVersion: $issuer_api
      name: $issues_name
      uid: $issues_uid
  type: Opaque
  data:
    tls.revoked-certs: "$revoked_certs_base64"
    tls.crl: "$crl_base64"
EOF
}

function annotation_revoke_set_to_false() {
  cert_name="$1"
  cert_namespace="$2"

  cat >> $KUBERNETES_PATCH_PATH <<EOF
---
operation: MergePatch
apiVersion: cert-manager.io/v1
kind: Certificate
namespace: $cert_namespace
name: $cert_name
ignoreMissingObject: true
mergePatch: |
  metadata:
    annotations:
      cm-crl-generator.citc.dev/revoke: 'false'
EOF
}

function annotation_set_certs_to_renew() {
  secret_name="$1"
  secret_namespace="$2"
  certs="$3"

  cat >> $KUBERNETES_PATCH_PATH <<EOF
---
operation: MergePatch
apiVersion: "v1"
kind: Secret
name: $secret_name
namespace: $secret_namespace
ignoreMissingObject: true
mergePatch: |
  metadata:
    annotations:
      cm-crl-generator.citc.dev/certs-to-renew: "$certs"
EOF
}

function delete_crl_secret() {
  secret_name="$1"
  secret_namespace="$2"

  cat > $KUBERNETES_PATCH_PATH <<EOF
---
operation: Delete
apiVersion: v1
kind: Secret
name: $secret_name
namespace: $secret_namespace
EOF
}

if [[ $1 == "--config" ]] ; then
  cat lib/generate-crl.config.yaml
else
  bindings_count=$(jq -r '. | length' "${BINDING_CONTEXT_PATH}")
  for ((b=0;b<bindings_count;b++)); do
    binding=$(jq -r '.['$b'].binding' "${BINDING_CONTEXT_PATH}")
    if [[ "$binding" == "certs-renew" ]] ; then
      # Renew certs if needs
      certs_to_renew=$(jq -r '.['$b'].object.metadata.annotations."cm-crl-generator.citc.dev/certs-to-renew"' "${BINDING_CONTEXT_PATH}")
      if [ ! "$certs_to_renew" == "null" ] && [ ! "$certs_to_renew" == "" ] ; then
        secret_name_crl=$(jq -r '.['$b'].object.metadata.name' "${BINDING_CONTEXT_PATH}")
        secret_namespace_crl=$(jq -r '.['$b'].object.metadata.namespace' "${BINDING_CONTEXT_PATH}")

        IFS=',' read -r -a certs_array <<< "$certs_to_renew"
        certs_array_count=${#certs_array[@]}
        for ((j=0;j<certs_array_count;j++)); do
          namespace_cert_to_revoke=$(echo "${certs_array[$j]}" | awk -F / '{ print $1 }')
          name_cert_to_revoke=$(echo "${certs_array[$j]}" | awk -F / '{ print $2 }')
          echo "Cert $namespace_cert_to_revoke/$name_cert_to_revoke to be renewed"
          cmctl renew -n $namespace_cert_to_revoke $name_cert_to_revoke
          annotation_set_certs_to_renew "$secret_name_crl" "$secret_namespace_crl" ""
        done
      fi
      break
    fi

    ca_issuers=$(jq -r '.['$b'].snapshots.issuer[] | select(.object.spec.ca != null)' "${BINDING_CONTEXT_PATH}")
    ca_clusterissuers=$(jq -r '.['$b'].snapshots.clusterissuer[] | select(.object.spec.ca != null)' "${BINDING_CONTEXT_PATH}")
    issuers=$(echo "${ca_issuers}${ca_clusterissuers}" | jq -n '. |= [inputs]')
    issuers_count=$(echo "$issuers" | jq -r '. | length')
    for ((i=0;i<issuers_count;i++)); do
      issuer_name=$(echo "${issuers}" | jq -r '.['$i'].object.metadata.name')
      issuer_namespace=$(echo "${issuers}" | jq -r '.['$i'].object.metadata.namespace')
      if [[ "$issuer_namespace" == "null" ]] ; then
        issuer_namespace="${CERT_MANAGER_NAMESPACE}"
      fi
      issuer_secret_name_crl="${issuer_name}-crl"
      
      crl_enabled=$(echo "${issuers}" | jq -r '.['$i'].object.metadata.annotations."cm-crl-generator.citc.dev/crl-enabled"')
      if [ "$crl_enabled" == "null" ] || [ "$crl_enabled" == "false" ] ; then
        secret_crl=$(jq -r '.['$b'].snapshots.secrets[] | select((.object.metadata.name == "'$issuer_secret_name_crl'") and (.object.metadata.namespace == "'$issuer_namespace'"))' "${BINDING_CONTEXT_PATH}")
        if [[ ! "$secret_crl" == "" ]] ; then
          echo "CRL secret $issuer_namespace/$issuer_secret_name_crl to be removed"
          delete_crl_secret "$issuer_secret_name_crl" "$issuer_namespace"
        fi
        break  
      fi

      issuer_api_version=$(echo "${issuers}" | jq -r '.['$i'].object.apiVersion')
      issuer_kind=$(echo "${issuers}" | jq -r '.['$i'].object.kind')
      issuer_uid=$(echo "${issuers}" | jq -r '.['$i'].object.metadata.uid')
      issuer_ca_secret_name=$(echo "${issuers}" | jq -r '.['$i'].object.spec.ca.secretName')

      cert_folder="${issuer_namespace}_${issuer_name}"
      mkdir -p /tmp/${cert_folder}

      is_need_to_generate_crl=false
      
      # Check secret CRL exists
      secret_crl=$(jq -r '.['$b'].snapshots.secrets[] | select((.object.metadata.name == "'$issuer_secret_name_crl'") and (.object.metadata.namespace == "'$issuer_namespace'"))' "${BINDING_CONTEXT_PATH}")
      secret_crl_tls_revoked_certs=""
      secret_crl_tls_revoked_certs_array=()
      if [[ "$secret_crl" == "" ]] ; then
        is_need_to_generate_crl=true
      else
        secret_crl_tls_revoked_certs=$(echo "$secret_crl" | jq -r '.object.data["tls.revoked-certs"]' | base64 -d)
        secret_crl_tls_revoked_certs_temp=$(echo "$secret_crl_tls_revoked_certs" | sed -e 's/-----END CERTIFICATE-----/-----END CERTIFICATE-----,/g' | tr -d '\n')
        IFS=',' read -r -a secret_crl_tls_revoked_certs_array <<< "$secret_crl_tls_revoked_certs_temp"
      fi
      
      #Check exists certs to revoke
      certs_to_revoke=$(jq -r '.['$b'].snapshots.certs[] | select((.object.metadata.annotations."cm-crl-generator.citc.dev/revoke" == "true") and (.object.spec.issuerRef.name == "'$issuer_name'") and (.object.spec.issuerRef.kind == "'$issuer_kind'"))' "${BINDING_CONTEXT_PATH}" | jq --slurp '.')
      certs_to_revoke_count=$(echo "$certs_to_revoke" | jq -r '. | length')
      if [[ $certs_to_revoke_count -gt 0 ]] ; then
        echo "Found ${certs_to_revoke_count} certificate(s) to revoke for issuer ${issuer_namespace}/${issuer_name}"
      fi
      
      for ((k=0;k<certs_to_revoke_count;k++)); do
        certs_to_renew=""
        name_cert_to_revoke=$(echo "${certs_to_revoke}" | jq -r '.['$k'].object.metadata.name')
        namespace_cert_to_revoke=$(echo "${certs_to_revoke}" | jq -r '.['$k'].object.metadata.namespace')
        secret_name_cert_to_revoke=$(echo "${certs_to_revoke}" | jq -r '.['$k'].object.spec.secretName')

        # Check secret exist
        secret_json=$(kubectl get secret -n "$namespace_cert_to_revoke" "$secret_name_cert_to_revoke" -o json 2>/dev/null)
        if [[ "$secret_json" == "" ]] ; then
          echo "Secret ${namespace_cert_to_revoke}/${secret_name_cert_to_revoke} doesn't exist, skip cert until next reconciliation"
          break
        fi
        secret_cert_pem=$(echo "${secret_json}" | jq -r '.data["tls.crt"]' | base64 -d)
        secret_cert_pem_temp=$(echo "$secret_cert_pem" | tr -d '\n')
        cert_already_exist=false
        secret_crl_tls_revoked_certs_array_length=${#secret_crl_tls_revoked_certs_array[@]}
        for ((p=0; p<${secret_crl_tls_revoked_certs_array_length}; p++)); do
          if [[ "${secret_crl_tls_revoked_certs_array[$p]}" == "$secret_cert_pem_temp" ]] ; then
            cert_already_exist=true
            break
          fi
        done

        annotation_revoke_set_to_false "$name_cert_to_revoke" "$namespace_cert_to_revoke"

        if [[ "$cert_already_exist" == "false" ]] ; then
          is_need_to_generate_crl=true

          # Add cert to list for renew
          if [[ "$certs_to_renew" == "" ]] ; then
            certs_to_renew+="${namespace_cert_to_revoke}/${name_cert_to_revoke}"
          else
            certs_to_renew+=",${namespace_cert_to_revoke}/${name_cert_to_revoke}"
          fi
          # Add cert to list for revoke
          if [[ "$secret_crl_tls_revoked_certs" == "" ]] ; then
            secret_crl_tls_revoked_certs+="${secret_cert_pem}"
          else
            secret_crl_tls_revoked_certs+=$'\n'"${secret_cert_pem}"
          fi
          echo "Cert $namespace_cert_to_revoke/$name_cert_to_revoke to be revoked"
        else
          echo "Cert $namespace_cert_to_revoke/$name_cert_to_revoke already revoked"
        fi
      done 

      if $is_need_to_generate_crl; then
        # Check secret exist
        ca_cert=$(kubectl get secret -n "$issuer_namespace" "$issuer_ca_secret_name" -o json 2>/dev/null)
        if [[ "$ca_cert" == "" ]] ; then
          echo "Secret ${issuer_namespace}/${issuer_ca_secret_name} doesn't exist, skip issuer until next reconciliation"
          break
        fi

        # Put CA cert and key to folder
        ca_cert_pem=$(echo "${ca_cert}" | jq -r '.data["tls.crt"]' | base64 -d)
        ca_key_pem=$(echo "${ca_cert}" | jq -r '.data["tls.key"]' | base64 -d)
        echo "$ca_cert_pem" > /tmp/${cert_folder}/ca.pem
        echo "$ca_key_pem" > /tmp/${cert_folder}/ca-key.pem

        # Put generate config to folder
        crl_next_update_date=$(certtool --certificate-info --infile /tmp/${cert_folder}/ca.pem | grep "Not After" | sed 's/.*: //')
        echo 'crl_next_update_date="'$crl_next_update_date'"' > /tmp/${cert_folder}/config.cfg
        
        # Generate CRL secret
        load_revoked_certs_param=""
        if [[ "$secret_crl" == "" ]] ; then
          echo "Create empty CRL secret ${issuer_namespace}/${issuer_secret_name_crl}"
        else
          echo "Update CRL secret ${issuer_namespace}/${issuer_secret_name_crl}"
          echo "$secret_crl_tls_revoked_certs" > /tmp/${cert_folder}/revoked-certs.pem
          load_revoked_certs_param="--load-certificate /tmp/${cert_folder}/revoked-certs.pem"
        fi
        certtool --generate-crl --no-text --template /tmp/${cert_folder}/config.cfg --load-ca-privkey /tmp/${cert_folder}/ca-key.pem --load-ca-certificate /tmp/${cert_folder}/ca.pem $load_revoked_certs_param --outfile /tmp/${cert_folder}/crl.pem
        generated_crl=$(cat /tmp/${cert_folder}/crl.pem)
        generate_crl_secret "$issuer_api_version" "$issuer_kind" "$issuer_uid" "$issuer_name" "$issuer_namespace" "$issuer_secret_name_crl" "$secret_crl_tls_revoked_certs" "$generated_crl" "$certs_to_renew"
      fi
      rm -rf /tmp/${cert_folder}
    done
  done
fi

exit 0
