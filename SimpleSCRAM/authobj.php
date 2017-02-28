<?php
	class AuthObject
	{
		public $userName;
		public $salt;
		public $clientNonce;
		public $serverNonce;
		public $iterationCount;
		public $isAuthenticated;
		public $storedKey;
		public $serverKey;
		
		public function __construct ($UserName, $Salt, $ClientNonce, $ServerNonce, $IterationCount, $IsAuthenticated, $StoredKey, $ServerKey) {
			$this->userName = $UserName;
			$this->salt = $Salt;
			$this->clientNonce = $ClientNonce;
			$this->serverNonce = $ServerNonce;
			$this->iterationCount = $IterationCount;
			$this->isAuthenticated = $IsAuthenticated;
			$this->storedKey = $StoredKey;
			$this->serverKey = $ServerKey;
		}
	}
	
	function setAuthObject($obj) {
		$_SESSION['authObj'] = NULL;
		$_SESSION['authObj'] = $obj;
	}
	
	function getAuthObj() {
		if(isset($_SESSION['authObj'])) {
			$obj = $_SESSION['authObj'];
			return $obj;
		}
		else {
			return NULL;
		}
	}
	
	function destroyAuthObj() {
		$_SESSION['authObj'] = NULL;
	}
?>
