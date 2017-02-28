<?php
	include("authobj.php");
	session_start();
	include("DB.php");
	include("encrypt.php");
	
	function startsWith($haystack, $needle)	{
		$length = strlen($needle);
		return (substr($haystack, 0, $length) === $needle);
	}
	
	if(isset($_POST["s"])) {
		
		// Post params set to try logging in with initial message
		if($_POST["s"] == "LOGIN" && isset($_POST["initialMsg"])) {
			
			$userName = "";
			$clientNonce = "";
			
			// n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
			$clientInitialMessage = trim($_POST["initialMsg"]);
			
			// Note that the client's first message will always start with "n", "y",
			// or "p"; otherwise, the message is invalid and authentication MUST fail.
			if(!startsWith($clientInitialMessage, "n") && !startsWith($clientInitialMessage, "y") && !startsWith($clientInitialMessage, "p")) {
				// authentication fails
				destroyAuthObj();
				echo "e=other-error";
				return;
			}
			
			$parts = explode(",", $clientInitialMessage);
			$usernameFound = false;
			$clientNonceFound = false;
			foreach ($parts as $part) {
				if(!isset($part)) continue;
				
				// fetch username
				if(substr($part, 0, 2) == "n=") {
					$userName = substr($part, 2);
					if(empty($userName)) {
						// If the preparation of the username fails or
						// results in an empty string, the server SHOULD abort the authentication exchange.	
						destroyAuthObj();
						echo "e=other-error";
						return;
					}
					$usernameFound = true;
				}
				
				// fetch user nonce
				if(substr($part, 0, 2) == "r=") {
					$clientNonce = substr($part, 2);
					if(empty($clientNonce)) {
						destroyAuthObj();
						echo "e=other-error";
						return;
					}
					$clientNonceFound = true;
				}
			}
			
			if(!$usernameFound || !$clientNonceFound) {
				// client didn't send username or nonce
				destroyAuthObj();
				echo "e=other-error";
				return;
			}
			
			
			$userInfo = DB::getUser($userName);
			if($userInfo) {
				// $serverNonce = ENC::generateSalt();
				// test vector
				$serverNonce = "3rfcNHYJY1ZVvWVs7j";
				
				$authObj = new AuthObject($userName, $userInfo["salt"], $clientNonce, $serverNonce, $userInfo["iteration"], false, $userInfo["storedKey"], $userInfo["serverKey"]);
				setAuthObject($authObj);
				
				$serverResponse = "r=" . $clientNonce . $serverNonce . ",s=" . $userInfo["salt"] . ",i=" . $userInfo["iteration"];
				echo $serverResponse;
			}
			else {
				// No such username
				destroyAuthObj();
				echo "e=unknown-user";
				return;
			}
		}
		
		// Post params set to try logging in with final message
		if($_POST["s"] == "LOGIN" && isset($_POST["finalMsg"])) {
			$clientFinalMessage = trim($_POST["finalMsg"]);
			// c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
			
			// c: This REQUIRED attribute specifies the base64-encoded GS2 header
			// and channel binding data.
			if(!startsWith($clientFinalMessage, "c")) {
				// authentication fails
				destroyAuthObj();
				echo "e=unsupported-channel-binding-type";
				return;
			}
			
			$concatNonce = ""; 
			$clientProof = "";
			
			$parts = explode(",", $clientFinalMessage);
			foreach ($parts as $part) {
				if(!isset($part)) continue;
				
				// fetch concatenated nonce
				if(substr($part, 0, 2) == "r=") {
					$concatNonce = substr($part, 2);
				}
				
				// fetch client proof
				if(substr($part, 0, 2) == "p=") {
					$binary = ENC::Base64_Decode(substr($part, 2));
					$clientProof = bin2hex($binary);
				}
			}
			
			if(empty($concatNonce) || empty($clientProof)) {
				destroyAuthObj();
				echo "e=other-error";
				return;
			}
			
			$authObj = getAuthObj();
			$userName = $authObj->userName;
			$salt = $authObj->salt;
			$clientNonce = $authObj->clientNonce;
			$serverNonce = $authObj->serverNonce;
			$iterationCount = $authObj->iterationCount;
			$isAuthenticated = $authObj->isAuthenticated;
			$storedKey = $authObj->storedKey;
			$serverKey = $authObj->serverKey;
			
			// The server MUST verify that the
			// nonce sent by the client in the second message is the same as the
			// one sent by the server in its first message.
			if($concatNonce != ($clientNonce.$serverNonce)) {
				destroyAuthObj();
				echo "e=other-error";
				return;
			}
			
			
			// server regenerates the AuthMessage and retrieves the StoredKey from DB to calculate ClientSignature
			$authMessage = "n=user,r=".$clientNonce.",r=".$clientNonce.$serverNonce.",s=".$salt.",i=".$iterationCount.",c=".(ENC::Base64_Encode("n,,")).",r=".$clientNonce.$serverNonce;
			// ClientSignature = HMAC(StoredKey, AuthMessage)
			$clientSignature = ENC::hashHMAC_SHA_1($authMessage, hex2bin($storedKey));
			// ClientKey = ClientProof XOR ClientSignature
			$clientKey = bin2hex(pack('H*', $clientProof) ^ pack('H*', $clientSignature));
			// StoredKey = H(ClientKey)
			$calcStoredKey = ENC::hashSHA_1(hex2bin($clientKey));
			
			if($storedKey == $calcStoredKey) {
				// ---------------------------------
				// client successfully authenticated
				// ---------------------------------
				$authObj->isAuthenticated = true;
				setAuthObject($authObj);
				// now generate and send ServerSignature
				// ServerSignature = HMAC(ServerKey, AuthMessage)
				$serverSignature = ENC::hashHMAC_SHA_1($authMessage, hex2bin($serverKey));
				echo "v=".(ENC::Base64_Encode(hex2bin($serverSignature)));
			}
			else {
				// --------------------------
				// client cannot authenticate
				// --------------------------
				destroyAuthObj();
				echo "e=invalid-proof!";
				return;
			}
			
		}
		
	}
	else {
		// service not described
		echo "invalid call";
	}
?>
