<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		
		<title>Simple SCRAM | İsmail Hakkı Parlak</title>
		
		<link rel="stylesheet" href="css/style.css">
		
		<script type="text/javascript" src="scripts/jquery-3.1.1.js"></script>
		<script type="text/javascript" src="scripts/hmac-sha1.js"></script>
		<script type="text/javascript" src="scripts/pbkdf2.js"></script>
		<script type="text/javascript" src="scripts/enc-base64.js"></script>
		<script type="text/javascript">
			// encapsulated CryptoJS functionalities
			
			// SHA-1
			function hashSHA_1(input) {
				var wordArray = CryptoJS.enc.Hex.parse(input);
				var hash = CryptoJS.SHA1(wordArray);
				return hash.toString(CryptoJS.enc.Hex);
			}
			
			// HMAC-SHA-1
			function hashHMAC_SHA_1(input, key) {
				var wordArrInput = CryptoJS.enc.Hex.parse(input);
				var wordArrKey = CryptoJS.enc.Utf8.parse(key);
				var hash = CryptoJS.HmacSHA1(wordArrKey, wordArrInput);
				return hash.toString(CryptoJS.enc.Hex);
			}
			
			// Generate salt
			function generateSalt() {
				var salt = CryptoJS.lib.WordArray.random(18);
				return salt.toString(CryptoJS.enc.Base64);
			}
			
			// Base64 encode
			function Base64_Encode(input) {
				var wordArray = CryptoJS.enc.Utf8.parse(input);
				return CryptoJS.enc.Base64.stringify(wordArray);
			}
			
			// Base64 decode
			function Base64_Decode(input) {
				var wordArray = CryptoJS.enc.Base64.parse(input);
				return wordArray.toString(CryptoJS.enc.Utf8);
			}
			
			// Hi
			function Hi(input, salt, i) {
				var wordArray = CryptoJS.enc.Base64.parse(salt);
				var hash = CryptoJS.PBKDF2(input, wordArray, {iterations: i, keySize: 160/32, hasher: CryptoJS.algo.SHA1});
				return hash.toString(CryptoJS.enc.Hex);
			}
			
			// XOR hex strings
			function XOR(num1, num2) {
				num1 = "" + num1 + "";
				num2 = "" + num2 + "";
				if(num1.length != num2.length) {
					console.log("Does not match:", num1, num2);
					return false;
				}
				
				var arr1 = num1.match(/.{1,2}/g);
				var arr2 = num2.match(/.{1,2}/g);
				var res = "";
				for(var i=0; i<arr1.length; i++) {
					var h1 = parseInt(arr1[i], 16);
					var h2 = parseInt(arr2[i], 16);
					var xord = ("00" + (h1 ^ h2).toString(16)).substr(-2);
					res += xord;
				}
				
				return res;
			}
		</script>
	</head>
	<body>
		
		<div class="login">
			<div class="login-screen">
				<div class="app-title">
					<h1>Login</h1>
				</div>
				
				<div class="login-form">
					<div class="control-group">
						<input type="text" class="login-field" value="user" placeholder="username" id="login-name" autocomplete="off">
						<label class="login-field-icon fui-user" for="login-name"></label>
					</div>
					
					<div class="control-group">
						<input type="password" class="login-field" value="pencil" placeholder="password" id="login-pass" autocomplete="off">
						<label class="login-field-icon fui-lock" for="login-pass"></label>
					</div>
					
					<a class="btn btn-primary btn-large btn-block" href="#" id="btn-login">login</a>
				</div>
			</div>
		</div>
		
		<script type="text/javascript">
			
			$(document).ready(function() {
				// login button click event
				$("#btn-login").click(function(e) {
					e.preventDefault();
					
					var userName = $("#login-name").val().trim();
					if(!userName) {
						alert("Please enter your username!");
						$("#login-name").focus();
						return false;
					}
					
					var password = $("#login-pass").val().trim();
					if(!password) {
						alert("Please enter your password!");
						$("#login-pass").focus();
						return false;
					}
					// test vector
					var clientNonce = "fyko+d2lbbFgONRv9qkxdawL";
					// var clientNonce = generateSalt();
					// n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
					var initialMessage = "n,,n=" + userName + ",r=" + clientNonce;
					console.log("client's initialMessage:", initialMessage);
					console.log("...sending initialMessage to server...");
					$.ajax({
						method: "POST",
						url: "login_service.php",
						data: { s: "LOGIN", initialMsg: initialMessage },
						success: function(m) {
							console.log("...server replied to initial client message...");
							var serverFirstMessage = m;
							if(serverFirstMessage.indexOf("e=") == 0) {
								console.log("SERVER RESPONDED WITH ERROR:", serverFirstMessage.substr(2));
								console.log("TERMINATING AUTHENTICATION");
								return false;
							}
							
							var parts = serverFirstMessage.split(",");
							if(parts.length < 3) {
								console.log("INITIAL SERVER MESSAGE IS WRONG FORMATTED", parts);
								console.log("TERMINATING AUTHENTICATION");
								return false;
							}
							
							
							// "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
							console.log("serverFirstMessage:", serverFirstMessage);
							
							var cNonceSNonce, serverNonce, serverSalt, iterationCount;
							
							for (var i = 0; i < parts.length; i++) {
								var part = parts[i];
								// get server nonce
								if(part.indexOf("r=") == 0) {
									cNonceSNonce = part.substr(2);
									if(!cNonceSNonce.indexOf(clientNonce) == 0) {
										// The client MUST verify that the initial
										// part of the nonce used in subsequent messages is the same as the
										// nonce it initially specified.
										console.log("SENT CLIENT NONCE DOES NOT MATCH THE RECIEVED NONCE", clientNonce, cNonceSNonce);
										console.log("TERMINATING AUTHENTICATION");
										return false;
									}
									serverNonce = cNonceSNonce.substr(clientNonce.length);
								}
								// get server salt
								if(part.indexOf("s=") == 0) {
									serverSalt = part.substr(2);
								}
								// get iteration count
								if(part.indexOf("i=") == 0) {
									iterationCount = parseInt(part.substr(2));
								}
							}
							
							if(!serverNonce || !serverSalt || !iterationCount) {
								console.log("SERVER MESSAGE HAS MISSING FIELDS [NONCE, SALT, ITERATION COUNT]");
								console.log("TERMINATING AUTHENTICATION");
								return false;
							}
							
							// client computes..
							console.log("...computing client final message...");
							
							var clientFinalMessageBare = "c=" + Base64_Encode("n,,") + ",r=" + cNonceSNonce;
							console.log("clientFinalMessageBare:", clientFinalMessageBare);
							
							console.log("......computing salted password......");
							console.log("......please wait....................");
							var saltedPassword = Hi(password, serverSalt, iterationCount);
							console.log("saltedPassword:", saltedPassword);
							
							var clientKey = hashHMAC_SHA_1(saltedPassword, "Client Key");
							console.log("clientKey:", clientKey);
							
							var storedKey = hashSHA_1(clientKey);
							console.log("storedKey:", storedKey);
							
							var authMessage = "n=" + userName + ",r=" + clientNonce + "," + serverFirstMessage + "," + clientFinalMessageBare;
							console.log("authMessage:", authMessage);
							
							var clientSignature = hashHMAC_SHA_1(storedKey, authMessage);
							console.log("clientSignature:", clientSignature);
							
							var clientProof = XOR(clientKey, clientSignature);
							console.log("clientProof:", clientProof);
							
							var waCP = CryptoJS.enc.Hex.parse(clientProof);
							var clientFinalMessage = clientFinalMessageBare + ",p=" + waCP.toString(CryptoJS.enc.Base64);
							console.log("clientFinalMessage:", clientFinalMessage);
							
							// send clientFinalMessage to server
							console.log("...sending clientFinalMessage to server...");
							// starting ajax call
							$.ajax({
								method: "POST",
								url: "login_service.php",
								data: { s: "LOGIN", finalMsg: clientFinalMessage },
								success: function(m) {
									console.log("...server replied to client's final message...");
									var serverFinalMessage = m;
									console.log("serverFinalMessage:", serverFinalMessage);
									
									if(serverFinalMessage.indexOf("e=") == 0) {
										console.log("SERVER RESPONDED WITH ERROR:", serverFinalMessage.substr(2));
										console.log("TERMINATING AUTHENTICATION");
										return false;
									}
									
									if(!serverFinalMessage || !serverFinalMessage.indexOf("v=") == 0) {
										console.log("SERVER MESSAGE HAS MISSING FIELDS [SIGNATURE]");
										console.log("TERMINATING AUTHENTICATION");
										return false;
									}
									else {
										// server sent a verification code
										// this means client is authenticated to server
										console.log("---------------------");
										console.log("CLIENT AUTHENTICATED!");
										console.log("---------------------");
									}
									
									var serversSignV = serverFinalMessage.substr(2);
									
									var serverKey = hashHMAC_SHA_1(saltedPassword, "Server Key");
									console.log("client computes serverKey:", serverKey);
									
									var serverSignature = hashHMAC_SHA_1(serverKey, authMessage);
									console.log("client computes serverSignature:", serverSignature);
									
									var waSS = CryptoJS.enc.Hex.parse(serverSignature);
									var serverSignature64 = waSS.toString(CryptoJS.enc.Base64);
									console.log("client computes serverSignature in Base64:", serverSignature64);
									// verify server signature
									if(serverSignature64 == serversSignV) {
										// server verified
										console.log("---------------------");
										console.log("SERVER AUTHENTICATED!");
										console.log("---------------------");
									}
									else {
										// server verification failed
										console.log("-----------------------------");
										console.log("SERVER AUTHENTICATION FAILED!");
										console.log("-----------------------------");
									}
								},
								error: function(m) {
									console.log("Exception:", m);
									return false;
								}
							});
							// eof ajax call
							
						},
						error: function(m) {
							console.log("Exception:", m);
							return false;
						}
					});
					// eof ajax call: outer
				});
				// eof login button click event				
			});
		</script>
		
	</body>
</html>
