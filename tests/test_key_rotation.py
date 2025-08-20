#!/usr/bin/env python3
"""
Test script for OIDC key rotation endpoints
Usage: python test_key_rotation.py
"""

import requests
import json
import time
from typing import Dict, Any

BASE_URL = "http://localhost:9400"
CLIENT_ID = "ae03b8fd-627c-419a-b8ee-a36076f01303"
CLIENT_SECRET = "IXhd-qoD5oqvUnrr2aISDQ"
REDIRECT_URI = "http://localhost/callback"

def test_key_rotation():
    """Test key rotation without full auth flow"""
    print("🔐 Testing OIDC Key Rotation...\n")
    
    # 1. First check JWKS to see current keys
    print("1. Checking initial JWKS...")
    jwks_before = get_jwks()
    initial_kids = [key["kid"] for key in jwks_before["keys"]]
    initial_modulus = {key["kid"]: key["n"] for key in jwks_before["keys"]}
    print(f"   Initial KIDs: {initial_kids}")
    
    # 2. Rotate keys
    print("2. Rotating keys...")
    rotate_response = rotate_keys()
    new_kid = rotate_response.get("new_kid")
    print(f"   New KID: {new_kid}")
    
    # 3. Check JWKS after rotation
    print("3. Checking JWKS after rotation...")
    jwks_after = get_jwks()
    after_kids = [key["kid"] for key in jwks_after["keys"]]
    after_modulus = {key["kid"]: key["n"] for key in jwks_after["keys"]}
    print(f"   KIDs after rotation: {after_kids}")
    
    # 4. Verify both old and new keys are present
    print("4. Verifying key preservation...")
    for kid in initial_kids:
        assert kid in after_kids, f"Old key {kid} missing from JWKS after rotation"
    assert new_kid in after_kids, f"New key {new_kid} missing from JWKS"
    print("   ✅ All keys preserved correctly")
    
    # 5. Test multiple rotations
    print("5. Testing multiple rotations...")
    previous_kids = after_kids.copy()
    previous_modulus = after_modulus.copy()
    
    for i in range(2):
        rotate_response = rotate_keys()
        newest_kid = rotate_response.get("new_kid")
        jwks_latest = get_jwks()
        latest_kids = [key["kid"] for key in jwks_latest["keys"]]
        latest_modulus = {key["kid"]: key["n"] for key in jwks_latest["keys"]}
        
        # Verify all previous keys are still there
        for kid in previous_kids:
            assert kid in latest_kids, f"Key {kid} lost during rotation {i+1}"
        
        assert newest_kid in latest_kids, f"New key {newest_kid} not in JWKS"
        print(f"   ✅ Rotation {i+1}: {len(latest_kids)} keys total")
        previous_kids = latest_kids
        previous_modulus = latest_modulus
    
    # 6. FINAL JWKS VERIFICATION - Ensure keys have actually changed
    print("\n6. 🔍 FINAL JWKS VERIFICATION - Ensuring keys have changed...")
    final_jwks = get_jwks()
    final_kids = [key["kid"] for key in final_jwks["keys"]]
    final_modulus = {key["kid"]: key["n"] for key in final_jwks["keys"]}
    
    print(f"   Final KIDs: {final_kids}")
    print(f"   Total keys in JWKS: {len(final_kids)}")
    
    # Verify we have more than just the initial key
    assert len(final_kids) > len(initial_kids), "No new keys were added to JWKS!"
    print(f"   ✅ Key count increased from {len(initial_kids)} to {len(final_kids)}")
    
    # Verify all keys have unique modulus values (different RSA keys)
    modulus_values = list(final_modulus.values())
    unique_modulus = set(modulus_values)
    assert len(modulus_values) == len(unique_modulus), "Duplicate modulus values found - keys are not unique!"
    print(f"   ✅ All {len(unique_modulus)} keys have unique RSA modulus values")
    
    # Verify the new key is different from original keys
    if new_kid in initial_modulus:
        assert final_modulus[new_kid] != initial_modulus[new_kid], "Rotated key has same modulus as original!"
    print("   ✅ Rotated keys have different cryptographic material")
    
    # Print key details for verification
    print("\n   📋 Key Details:")
    for kid in final_kids:
        key_type = "ORIGINAL" if kid in initial_kids else "ROTATED" 
        modulus_short = str(final_modulus[kid])[:20] + "..." if len(str(final_modulus[kid])) > 20 else str(final_modulus[kid])
        print(f"      {kid} ({key_type}): modulus={modulus_short}")
    
    print("\n🎉 All key rotation tests passed!")
    print(f"   ✅ Key rotation successful: {len(initial_kids)} → {len(final_kids)} keys")
    print(f"   ✅ All keys are cryptographically unique")
    print(f"   ✅ JWKS endpoint properly maintains key history")

def rotate_keys() -> Dict[str, Any]:
    """Rotate keys and return response"""
    response = requests.post(f"{BASE_URL}/oauth2/keys/rotate")
    response.raise_for_status()
    return response.json()

def get_jwks() -> Dict[str, Any]:
    """Get JWKS endpoint data"""
    response = requests.get(f"{BASE_URL}/jwks")
    response.raise_for_status()
    return response.json()

def get_token_kid(token: str) -> str:
    """Extract KID from token header"""
    try:
        header = token.split(".")[0]
        # Add padding if needed for base64 decode
        padding = len(header) % 4
        if padding:
            header += "=" * (4 - padding)
        
        import base64
        header_json = json.loads(base64.urlsafe_b64decode(header))
        return header_json["kid"]
    except:
        return "unknown"

def validate_token(token: str) -> bool:
    """Validate token against userinfo endpoint"""
    try:
        response = requests.get(
            f"{BASE_URL}/userinfo",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5
        )
        return response.status_code == 200
    except:
        return False

if __name__ == "__main__":
    try:
        test_key_rotation()
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)