<?php
	class DB 
	{
		private static $users = array(
		"user"=>array(
		"salt"=>"QSXCR+Q6sek8bf92", 
		"storedKey"=>"e9d94660c39d65c38fbad91c358f14da0eef2bd6", 
		"serverKey"=>"0fe09258b3ac852ba502cc62ba903eaacdbf7d31", 
		"iteration"=>4096)
		);
		
		// fetch user from DB, this is a fake DB ofcourse :)
		public static function getUser($username) {
			return isset(self::$users[$username]) ? self::$users[$username] : false;
		}
	}
?>
