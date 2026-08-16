rule ModelPoisoningAttack {
    meta:
        description = "Detects AI model poisoning attempts"
        severity = "critical"
        
    strings:
        $weight_tamper = { 48 89 E5 41 57 41 56 }
        $gradient_hack = "backward()" wide ascii
        $batch_poison = "DataLoader" wide ascii
        $model_inject = { 48 8D 15 ?? ?? ?? ?? }
        
    condition:
        3 of them
}

rule AIModelTheft {
    meta:
        description = "Detects AI model extraction attempts"
        severity = "critical"
        
    strings:
        $model_dump = "state_dict()" wide ascii
        $weight_extract = { 48 8B 45 ?? 48 89 45 ?? }
        $arch_steal = "model.architecture" wide ascii
        $param_copy = { 0F AE ?? 48 8B 45 }
        
    condition:
        3 of them
}

rule AdversarialAttack {
    meta:
        description = "Detects adversarial attacks on AI systems"
        severity = "critical"
        
    strings:
        $input_perturb = "add_noise" wide ascii
        $gradient_ascent = { 48 89 E5 41 56 41 55 }
        $fgsm_attack = "sign(data.grad)" wide ascii
        $patch_inject = { 48 8D 0D ?? ?? ?? ?? }
        
    condition:
        3 of them
}

rule AIInferenceAttack {
    meta:
        description = "Detects AI inference manipulation"
        severity = "critical"
        
    strings:
        $confidence_tamper = "softmax" wide ascii
        $output_manip = { 48 8B 45 ?? 48 8D 15 }
        $prediction_hijack = "model.predict" wide ascii
        $inference_bypass = { 0F AE E8 48 8B }
        
    condition:
        3 of them
}

rule AISupplyChainAttack {
    meta:
        description = "Detects AI supply chain compromises"
        severity = "critical"
        
    strings:
        $pretrained_tamper = "load_pretrained" wide ascii
        $checkpoint_poison = { 48 89 E5 41 57 41 56 }
        $weight_backdoor = "load_state_dict" wide ascii
        $model_hub_exploit = { 48 8D 0D ?? ?? ?? ?? }
        
    condition:
        3 of them
}
