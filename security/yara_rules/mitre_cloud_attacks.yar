rule CloudCredentialAccess {
    meta:
        description = "Detects cloud credential access and theft attempts"
        severity = "critical"
        mitre_technique = "T1552"
        
    strings:
        $aws_cred = /.{20}(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}/ wide ascii
        $azure_token = "eyJ0eXAiOiJKV1QiL" wide ascii
        $gcp_key = "-----BEGIN PRIVATE KEY-----" wide ascii
        $kubectl_config = ".kube/config" wide ascii
        
    condition:
        any of them
}

rule ContainerEscape {
    meta:
        description = "Detects container escape techniques"
        severity = "critical"
        mitre_technique = "T1611"
        
    strings:
        $mount_escape = "docker.sock" wide ascii
        $privileged_flag = "--privileged" wide ascii
        $cap_admin = "CAP_SYS_ADMIN" wide ascii
        $cgroup_release = "notify_on_release" wide ascii
        
    condition:
        2 of them
}

rule CloudPersistence {
    meta:
        description = "Detects cloud-based persistence mechanisms"
        severity = "critical"
        mitre_technique = "T1098"
        
    strings:
        $lambda_backdoor = "CreateFunction" wide ascii
        $cronjob_persist = "CronJob" wide ascii
        $iam_backdoor = "CreateAccessKey" wide ascii
        $webhook_create = "MutatingWebhookConfiguration" wide ascii
        
    condition:
        2 of them
}

rule KubernetesAttack {
    meta:
        description = "Detects Kubernetes-specific attacks"
        severity = "critical"
        mitre_technique = "T1609"
        
    strings:
        $pod_exec = "pods/exec" wide ascii
        $priv_esc = "system:masters" wide ascii
        $admission_bypass = "ValidatingWebhookConfiguration" wide ascii
        $etcd_access = "etcdctl" wide ascii
        
    condition:
        2 of them
}

rule CloudDataExfil {
    meta:
        description = "Detects cloud data exfiltration methods"
        severity = "critical"
        mitre_technique = "T1537"
        
    strings:
        $s3_copy = "aws s3 cp" wide ascii
        $blob_download = "azure storage blob download" wide ascii
        $gsutil_copy = "gsutil cp" wide ascii
        $rclone_sync = "rclone sync" wide ascii
        
    condition:
        2 of them
}

rule ServerlessAttack {
    meta:
        description = "Detects serverless function attacks"
        severity = "critical"
        mitre_technique = "T1583"
        
    strings:
        $env_leak = "process.env" wide ascii
        $runtime_escape = "/proc/self/environ" wide ascii
        $temp_abuse = "/tmp" wide ascii
        $event_injection = "event.body" wide ascii
        
    condition:
        2 of them
}

rule CloudConfigTampering {
    meta:
        description = "Detects cloud configuration tampering"
        severity = "critical"
        mitre_technique = "T1574"
        
    strings:
        $terraform_mod = ".tf" wide ascii
        $cloudformation = "AWS::*" wide ascii
        $arm_template = "Microsoft.Resources" wide ascii
        $helm_tiller = "tiller" wide ascii
        
    condition:
        2 of them
}

rule ServiceMeshAttack {
    meta:
        description = "Detects service mesh exploitation"
        severity = "critical"
        mitre_technique = "T1562"
        
    strings:
        $istio_bypass = "istio-proxy" wide ascii
        $envoy_exploit = "envoy.admin" wide ascii
        $linkerd_tamper = "linkerd-proxy" wide ascii
        $mesh_routing = "VirtualService" wide ascii
        
    condition:
        2 of them
}

rule CloudAPIAbuse {
    meta:
        description = "Detects cloud API abuse patterns"
        severity = "high"
        mitre_technique = "T1552.005"
        
    strings:
        $metadata_server = "169.254.169.254" wide ascii
        $imds_token = "X-aws-ec2-metadata-token" wide ascii
        $azure_instance = "identity/oauth2/token" wide ascii
        $gcp_metadata = "metadata.google.internal" wide ascii
        
    condition:
        2 of them
}

rule CloudSupplyChain {
    meta:
        description = "Detects cloud supply chain attacks"
        severity = "critical"
        mitre_technique = "T1195"
        
    strings:
        $registry_tamper = "docker pull" wide ascii
        $package_inject = "requirements.txt" wide ascii
        $dependency_conf = "package-lock.json" wide ascii
        $image_backdoor = "FROM" wide ascii nocase
        
    condition:
        2 of them
}

rule CloudRansomware {
    meta:
        description = "Detects cloud-targeted ransomware"
        severity = "critical"
        mitre_technique = "T1486"
        
    strings:
        $bucket_encrypt = "ServerSideEncryption" wide ascii
        $key_deletion = "DeleteObject" wide ascii
        $volume_encrypt = "CreateSnapshot" wide ascii
        $backup_delete = "DeleteBackup" wide ascii
        
    condition:
        2 of them
}

rule ServiceAccountAbuse {
    meta:
        description = "Detects service account abuse"
        severity = "critical"
        mitre_technique = "T1078.004"
        
    strings:
        $token_mount = "serviceaccount/token" wide ascii
        $sa_escalation = "ClusterRoleBinding" wide ascii
        $token_theft = "bearer token" wide ascii nocase
        $sa_impersonation = "as=system:serviceaccount" wide ascii
        
    condition:
        2 of them
}
