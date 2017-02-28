<?php	
	class ENC 
	{
		// SHA-1
		public static function hashSHA_1($input) {
			return sha1($input);
		}	
		
		// HMAC-SHA-1
		public static function hashHMAC_SHA_1($input, $key) {
			return hash_hmac("sha1", $input, $key, false);
		}
		
		// Generate salt
		public static function generateSalt() {
			return base64_encode(mcrypt_create_iv(18, MCRYPT_DEV_URANDOM));
		}
		
		// Base64 encode
		public static function Base64_Encode($input) {
			return base64_encode($input);
		}
		
		// Base64 decode
		public static function Base64_Decode($input) {
			return base64_decode($input);
		}
		
		// Hi
		public static function Hi($input, $salt, $i) {
			return hash_pbkdf2("sha1", $input, $salt, $i, 32);
		}
	}
?>
