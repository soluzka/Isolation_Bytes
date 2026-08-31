// fuzzy_integration.yar
// Helper notes for adding fuzzy matching (ssdeep) to YARA rules.
// 1) Compute ssdeep of samples externally (ssdeep CLI or python ssdeep lib).
// 2) Add the computed ssdeep string to the rule's meta, e.g.:
//      meta:
//          ssdeep = "3:aBc...:..."
// 3) Use an external script to compare file ssdeep to rule meta ssdeep and decide matches;
//    YARA alone cannot compute ssdeep during rule evaluation.

// Example Python (pseudo):
// import ssdeep, yara
// rules = yara.compile("yara_rules.yar")
// target_hash = ssdeep.hash(open("sample.exe","rb").read())
// for r in rules:
//     if 'ssdeep' in r.meta:
//         score = ssdeep.compare(target_hash, r.meta['ssdeep'])
//         if score >= 60:
//             print("fuzzy match", r)

// Optional: pe.imphash() can be checked inside YARA if you know target imphashes;
// add imphash meta placeholders and compare in condition: pe.imphash() == "..."

// Replace TODO placeholders in rules with real hashes before using.
