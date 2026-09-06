"""Convert scikit-learn and LightGBM (EMBER) models to ONNX format
for use in the Android app via ONNX Runtime."""

import os
import sys
import joblib
import traceback

MODELS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'android', 'app', 'src', 'main', 'assets', 'models')

os.makedirs(OUTPUT_DIR, exist_ok=True)

def convert_sklearn_model(pkl_path, output_name, n_features=256):
    """Convert a scikit-learn .pkl model to ONNX."""
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    try:
        model = joblib.load(pkl_path)
    except Exception as e:
        print(f"  Failed to load {pkl_path}: {e}")
        return False

    # Determine if it's a pipeline with PCA/scaler
    try:
        initial_type = [('input', FloatTensorType([1, n_features]))]
        onnx_model = convert_sklearn(model, initial_types=initial_type, target_opset=15)
        output_path = os.path.join(OUTPUT_DIR, output_name)
        with open(output_path, 'wb') as f:
            f.write(onnx_model.SerializeToString())
        print(f"  Converted: {output_name} ({os.path.getsize(output_path)} bytes)")
        return True
    except Exception as e:
        # Try with different feature counts
        for nf in [2381, 1024, 128, 64, 32, 16, 8, 4, 2]:
            try:
                initial_type = [('input', FloatTensorType([1, nf]))]
                onnx_model = convert_sklearn(model, initial_types=initial_type, target_opset=15)
                output_path = os.path.join(OUTPUT_DIR, output_name)
                with open(output_path, 'wb') as f:
                    f.write(onnx_model.SerializeToString())
                print(f"  Converted: {output_name} with {nf} features ({os.path.getsize(output_path)} bytes)")
                return True
            except Exception:
                continue
        print(f"  Failed to convert {output_name}: {e}")
        return False

def convert_lightgbm_ember():
    """Convert the EMBER LightGBM model to ONNX."""
    ember_model_path = os.path.join(MODELS_DIR, 'ember_malware_model.txt')
    if not os.path.exists(ember_model_path):
        print(f"  EMBER model not found at {ember_model_path}")
        return False

    try:
        import lightgbm as lgb
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType

        # Load the LightGBM model
        booster = lgb.Booster(model_file=ember_model_path)

        # Convert to sklearn-compatible wrapper
        from lightgbm import LGBMClassifier
        clf = LGBMClassifier()
        clf._Booster = booster
        # We need to set the model string manually
        clf._n_features = 2381  # EMBER 2018 feature count

        # Use the ONNX LightGBM converter directly
        from onnxconverter_common.data_types import FloatTensorType as ONNXFloat
        from skl2onnx import convert_sklearn

        # Try direct conversion via the booster
        try:
            from onnxmltools.convert.lightgbm.operator_converters.LightGbm import \
                convert_lightgbm
            from onnxmltools.convert.common.data_types import FloatTensorType as XmlFloat
            import onnxmltools

            initial_type = [('input', XmlFloat([1, 2381]))]
            onnx_model = onnxmltools.convert_lightgbm(booster, initial_types=initial_type, target_opset=15)
            output_path = os.path.join(OUTPUT_DIR, 'ember_model.onnx')
            with open(output_path, 'wb') as f:
                f.write(onnx_model.SerializeToString())
            print(f"  Converted: ember_model.onnx ({os.path.getsize(output_path)} bytes)")
            return True
        except ImportError:
            # Fallback: use skl2onnx with a wrapper
            print("  onnxmltools not available, trying skl2onnx...")

            # Create a dummy LGBMClassifier and fit it with the booster
            initial_type = [('input', FloatTensorType([1, 2381]))]

            # Manually create the ONNX graph from the LightGBM model
            import numpy as np
            # Save booster as sklearn model
            model_str = booster.model_to_string()
            clf2 = LGBMClassifier(n_estimators=100)
            clf2._Booster = booster
            clf2._n_features = 2381
            clf2._n_classes = 2
            clf2._classes = np.array([0, 1])

            onnx_model = convert_sklearn(clf2, initial_types=initial_type, target_opset=15)
            output_path = os.path.join(OUTPUT_DIR, 'ember_model.onnx')
            with open(output_path, 'wb') as f:
                f.write(onnx_model.SerializeToString())
            print(f"  Converted: ember_model.onnx ({os.path.getsize(output_path)} bytes)")
            return True
    except Exception as e:
        print(f"  EMBER conversion failed: {e}")
        traceback.print_exc()
        return False

def main():
    print("=== Converting models to ONNX ===\n")

    # Convert EMBER model
    print("1. EMBER LightGBM model:")
    convert_lightgbm_ember()

    # Convert key scikit-learn models (most important ones for malware detection)
    key_models = [
        ('bodmas_malware_classifier.pkl', 'bodmas_malware.onnx'),
        ('bodmas_dnn_classifier.pkl', 'bodmas_dnn.onnx'),
        ('file_malware_classifier.pkl', 'file_malware.onnx'),
        ('malware_model.pkl', 'malware_generic.onnx'),
        ('ransomware_model.pkl', 'ransomware.onnx'),
        ('trojan_model.pkl', 'trojan.onnx'),
        ('spyware_model.pkl', 'spyware.onnx'),
        ('keylogger_model.pkl', 'keylogger.onnx'),
        ('rootkit_model.pkl', 'rootkit.onnx'),
        ('backdoor_model.pkl', 'backdoor.onnx'),
        ('botnet_model.pkl', 'botnet.onnx'),
        ('adware_model.pkl', 'adware.onnx'),
    ]

    print("\n2. Scikit-learn models:")
    for pkl_name, onnx_name in key_models:
        pkl_path = os.path.join(MODELS_DIR, pkl_name)
        if os.path.exists(pkl_path):
            print(f"  Converting {pkl_name}...")
            convert_sklearn_model(pkl_path, onnx_name)
        else:
            print(f"  Skip {pkl_name} (not found)")

    # List output
    print(f"\n=== Converted models in {OUTPUT_DIR} ===")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        if f.endswith('.onnx'):
            size = os.path.getsize(os.path.join(OUTPUT_DIR, f))
            print(f"  {f}: {size:,} bytes ({size/1024/1024:.1f} MB)")

if __name__ == '__main__':
    main()
