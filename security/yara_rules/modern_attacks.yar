rule ServerlessAttackPattern {
    meta:
        description = "Detects serverless function attacks and manipulation"
        severity = "critical"
        
    strings:
        $lambda_inject = "exports.handler" wide ascii
        $env_leak = "process.env" wide ascii
        $context_abuse = "context.clientContext" wide ascii
        $event_poison = { 22 65 76 65 6E 74 22 }
        
    condition:
        2 of them
}

rule K8sClusterAttack {
    meta:
        description = "Detects Kubernetes cluster attack patterns"
        severity = "critical"
        
    strings:
        $priv_esc = "system:masters" wide ascii
        $pod_exec = "pods/exec" wide ascii
        $service_account = "default/token" wide ascii
        $kube_inject = "kubectl exec" wide ascii
        
    condition:
        2 of them
}

rule ServiceMeshExploit {
    meta:
        description = "Detects service mesh exploitation"
        severity = "critical"
        
    strings:
        $istio_bypass = "istio-proxy" wide ascii
        $sidecar_tamper = "envoy.admin" wide ascii
        $mesh_route = "VirtualService" wide ascii
        $policy_bypass = "AuthorizationPolicy" wide ascii
        
    condition:
        2 of them
}

rule DevOpsToolchainAttack {
    meta:
        description = "Detects attacks on DevOps toolchain"
        severity = "critical"
        
    strings:
        $pipeline_inject = "jenkins.security" wide ascii
        $ci_poison = ".gitlab-ci.yml" wide ascii
        $action_tamper = "workflow_dispatch" wide ascii
        $build_compromise = "docker build" wide ascii
        
    condition:
        2 of them
}

rule MicroservicesAttack {
    meta:
        description = "Detects microservices-specific attacks"
        severity = "high"
        
    strings:
        $service_discovery = "eureka.client" wide ascii
        $config_poison = "spring.cloud.config" wide ascii
        $circuit_abuse = "hystrix.command" wide ascii
        $mesh_exploit = { 48 8B 45 ?? 48 8D 15 }
        
    condition:
        2 of them
}

rule ApiGatewayBypass {
    meta:
        description = "Detects API gateway security bypasses"
        severity = "critical"
        
    strings:
        $rate_limit = "X-RateLimit" wide ascii
        $auth_bypass = "Authorization:" wide ascii
        $route_tamper = "X-Forwarded" wide ascii
        $gateway_inject = { 48 89 E5 41 57 41 56 }
        
    condition:
        2 of them
}

rule GraphQLInjection {
    meta:
        description = "Detects GraphQL injection attacks"
        severity = "critical"
        
    strings:
        $introspection = "__schema" wide ascii
        $query_depth = "__typename" wide ascii
        $fragment_abuse = "... on" wide ascii
        $directive_inject = "@include" wide ascii
        
    condition:
        2 of them
}

rule EventStreamingAttack {
    meta:
        description = "Detects attacks on event streaming platforms"
        severity = "critical"
        
    strings:
        $kafka_exploit = "kafka.security" wide ascii
        $stream_poison = "KStream" wide ascii
        $pubsub_attack = "pubsub.googleapis" wide ascii
        $event_inject = { 48 8D 0D ?? ?? ?? ?? E8 }
        
    condition:
        2 of them
}

rule EdgeComputingExploit {
    meta:
        description = "Detects edge computing node exploitation"
        severity = "critical"
        
    strings:
        $edge_bypass = "edge.config" wide ascii
        $fog_compute = "fog.node" wide ascii
        $iot_hub = "iothub.device" wide ascii
        $edge_inject = { 48 89 E5 41 56 41 55 }
        
    condition:
        2 of them
}

rule InfraAsCodeAttack {
    meta:
        description = "Detects Infrastructure as Code attacks"
        severity = "critical"
        
    strings:
        $terraform_inject = "provider" wide ascii
        $cloudformation = "AWS::*" wide ascii
        $arm_template = "Microsoft.Resources" wide ascii
        $pulumi_attack = "pulumi.runtime" wide ascii
        
    condition:
        2 of them
}

rule ZeroTrustBypass {
    meta:
        description = "Detects Zero Trust architecture bypasses"
        severity = "critical"
        
    strings:
        $identity_forge = "sts.amazonaws" wide ascii
        $token_abuse = "Bearer " wide ascii
        $policy_bypass = "security.policy" wide ascii
        $context_spoof = { 48 8B 45 ?? 48 89 45 ?? }
        
    condition:
        2 of them
}

rule BlockchainNodeAttack {
    meta:
        description = "Detects blockchain node attacks"
        severity = "critical"
        
    strings:
        $consensus_tamper = "consensus.block" wide ascii
        $smart_contract = "contract.execute" wide ascii
        $chain_exploit = { 48 89 E5 41 57 41 56 }
        $wallet_attack = "wallet.sign" wide ascii
        
    condition:
        2 of them
}

rule MLModelAttack {
    meta:
        description = "Detects machine learning model attacks"
        severity = "critical"
        
    strings:
        $model_poison = "model.fit" wide ascii
        $inference_attack = "predict(" wide ascii
        $weight_tamper = { F3 0F 10 45 ?? F3 0F 11 }
        $gradient_hack = "optimizer.step" wide ascii
        
    condition:
        2 of them
}

rule QuantumComputeAttack {
    meta:
        description = "Detects quantum computing attacks"
        severity = "critical"
        
    strings:
        $qubit_tamper = "qbit.state" wide ascii
        $quantum_circuit = "circuit.append" wide ascii
        $superposition = { 48 8D 15 ?? ?? ?? ?? E8 }
        $entangle_hack = "entangle(" wide ascii
        
    condition:
        2 of them
}
