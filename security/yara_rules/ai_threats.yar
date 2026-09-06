rule ModelPoisoningAttack {
    meta:
        description = "Detects AI model poisoning attempts"
        severity = "critical"

    strings:
        $weight_tamper = "poison_weights" ascii wide nocase
        $gradient_hack = "gradient_hijack" ascii wide nocase
        $batch_poison = "poison_batch" ascii wide nocase
        $model_inject = "inject_backdoor_model" ascii wide nocase

    condition:
        2 of them
}

rule AIModelTheft {
    meta:
        description = "Detects AI model extraction attempts"
        severity = "critical"

    strings:
        $model_dump = "steal_model" ascii wide nocase
        $arch_steal = "extract_architecture" ascii wide nocase
        $param_copy = "copy_trained_weights" ascii wide nocase
        $api_scrape = "scrape_model_api" ascii wide nocase

    condition:
        2 of them
}

rule AdversarialAttack {
    meta:
        description = "Detects adversarial attacks on AI systems"
        severity = "critical"

    strings:
        $fgsm_attack = "fgsm_perturbation" ascii wide nocase
        $patch_inject = "adversarial_patch" ascii wide nocase
        $input_perturb = "perturb_input_malicious" ascii wide nocase
        $evasion = "model_evasion_attack" ascii wide nocase

    condition:
        2 of them
}

rule AIInferenceAttack {
    meta:
        description = "Detects AI inference manipulation"
        severity = "critical"

    strings:
        $confidence_tamper = "tamper_confidence" ascii wide nocase
        $prediction_hijack = "hijack_prediction" ascii wide nocase
        $inference_bypass = "bypass_inference" ascii wide nocase
        $output_manip = "manipulate_inference_output" ascii wide nocase

    condition:
        2 of them
}

rule AISupplyChainAttack {
    meta:
        description = "Detects AI supply chain compromises"
        severity = "critical"

    strings:
        $pretrained_tamper = "tamper_pretrained" ascii wide nocase
        $checkpoint_poison = "poison_checkpoint" ascii wide nocase
        $weight_backdoor = "backdoor_weights" ascii wide nocase
        $model_hub_exploit = "exploit_model_hub" ascii wide nocase

    condition:
        2 of them
}
