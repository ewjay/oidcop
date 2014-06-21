
DROP TABLE IF EXISTS `accounts`;

CREATE TABLE `accounts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `enabled` tinyint(4) DEFAULT '1',
  `login` varchar(255) NOT NULL,
  `crypted_password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


LOCK TABLES `accounts` WRITE;
/*!40000 ALTER TABLE `accounts` DISABLE KEYS */;
INSERT INTO `accounts` VALUES (1,1,'alice','b6263bb14858294c08e4bdfceba90363e10d72b4'),(2,1,'bob','cc8684eed2b6544e89242558df73a7208c9391b4');
/*!40000 ALTER TABLE `accounts` ENABLE KEYS */;
UNLOCK TABLES;


DROP TABLE IF EXISTS `clients`;
CREATE TABLE `clients` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id` varchar(255) NOT NULL,
  `client_id_issued_at` int(11) DEFAULT NULL,
  `client_secret` varchar(255) NOT NULL,
  `client_secret_expires_at` int(11) DEFAULT NULL,
  `registration_access_token` varchar(255) DEFAULT NULL,
  `registration_client_uri_path` varchar(255) DEFAULT NULL,
  `contacts` text,
  `application_type` varchar(255) DEFAULT NULL,
  `client_name` varchar(255) DEFAULT NULL,
  `logo_uri` varchar(255) DEFAULT NULL,
  `tos_uri` varchar(255) DEFAULT NULL,
  `redirect_uris` text,
  `token_endpoint_auth_method` varchar(255) DEFAULT NULL,
  `token_endpoint_auth_signing_alg` varchar(255) DEFAULT NULL,
  `policy_uri` varchar(255) DEFAULT NULL,
  `jwks_uri` varchar(255) DEFAULT NULL,
  `jwk_encryption_uri` varchar(255) DEFAULT NULL,
  `x509_uri` varchar(255) DEFAULT NULL,
  `x509_encryption_uri` varchar(255) DEFAULT NULL,
  `sector_identifier_uri` varchar(255) DEFAULT NULL,
  `javascript_origin_uris` text,
  `subject_type` varchar(255) DEFAULT NULL,
  `request_object_signing_alg` varchar(255) DEFAULT NULL,
  `userinfo_signed_response_alg` varchar(255) DEFAULT NULL,
  `userinfo_encrypted_response_alg` varchar(255) DEFAULT NULL,
  `userinfo_encrypted_response_enc` varchar(255) DEFAULT NULL,
  `id_token_signed_response_alg` varchar(255) DEFAULT NULL,
  `id_token_encrypted_response_alg` varchar(255) DEFAULT NULL,
  `id_token_encrypted_response_enc` varchar(255) DEFAULT NULL,
  `default_max_age` int(11) DEFAULT NULL,
  `require_auth_time` tinyint(1) DEFAULT NULL,
  `default_acr_values` varchar(255) DEFAULT NULL,
  `initiate_login_uri` varchar(255) DEFAULT NULL,
  `post_logout_redirect_uri` varchar(255) DEFAULT NULL,
  `request_uris` text,
  `grant_types` varchar(255) DEFAULT NULL,
  `response_types` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


DROP TABLE IF EXISTS `personas`;
CREATE TABLE `personas` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `persona_name` varchar(255) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `given_name` varchar(255) DEFAULT NULL,
  `given_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `given_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `family_name` varchar(255) DEFAULT NULL,
  `family_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `family_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `middle_name` varchar(255) DEFAULT NULL,
  `middle_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `middle_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `nickname` varchar(255) DEFAULT NULL,
  `preferred_username` varchar(255) DEFAULT NULL,
  `profile` varchar(255) DEFAULT NULL,
  `picture` varchar(255) DEFAULT NULL,
  `website` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `email_verified` tinyint(1) DEFAULT NULL,
  `gender` varchar(255) DEFAULT NULL,
  `birthdate` varchar(255) DEFAULT NULL,
  `zoneinfo` varchar(255) DEFAULT NULL,
  `locale` varchar(255) DEFAULT NULL,
  `phone_number` varchar(255) DEFAULT NULL,
  `phone_number_verified` tinyint(1) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `updated_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_personas_on_account_id_and_persona_name_idx` (`account_id`,`persona_name`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


LOCK TABLES `personas` WRITE;
/*!40000 ALTER TABLE `personas` DISABLE KEYS */;
INSERT INTO `personas` VALUES (1,1,'Default','Alice Yamada','ãƒ¤ãƒžãƒ€ã‚¢ãƒªã‚µ','å±±ç”°äºœç<90>†ç´—','Alice','ã‚¢ãƒªã‚µ','äºœç<90>†ç´—','Yamada','ãƒ¤ãƒžãƒ€','å±±ç”°','','','','Standard Alice','=Alice1','http://www.wonderland.com/alice','https://connect.openid4.us/abrp/smiling_woman.jpg','http://www.wonderland.com','alice@wonderland.com',1,'female','1988-08-08','America/Los_Angeles','en','1-81-234-234234234',1,'123 wonderland way','2013-08-21 18:16:09'),(2,1,'Shopping','Alice Yamada','ãƒ¤ãƒžãƒ€ã‚¢ãƒªã‚µ','å±±ç”°äºœç<90>†ç´—','Alice','ã‚¢ãƒªã‚µ','äºœç<90>†ç´—','Yamada','ãƒ¤ãƒžãƒ€','å±±ç”°','',NULL,NULL,'Shopping Alice','','http://www.wonderland.com/alice','https://connect.openid4.us/abrp/smiling_woman.jpg','http://www.wonderland.com','alice@wonderland.com',1,'female','1988-08-08','some zone','some locale','1-81-234-234234234',1,'123 wonderland way','2013-08-21 18:16:09'),(3,1,'Browsing','Alice Yamada','ãƒ¤ãƒžãƒ€ã‚¢ãƒªã‚µ','å±±ç”°äºœç<90>†ç´—','Alice','ã‚¢ãƒªã‚µ','äºœç<90>†ç´—','Yamada','ãƒ¤ãƒžãƒ€','å±±ç”°','','','','Browsing Alice','','http://www.wonderland.com/alice','https://connect.openid4.us/abrp/smiling_woman.jpg','http://www.wonderland.com','alice@wonderland.com',1,'female','1988-08-08','some zone','some locale','1-81-234-234234234',1,'123 wonderland way','2013-08-21 18:16:09'),(4,2,'Default','Bob Ikeda','ã‚¤ã‚±ãƒ€ãƒœãƒ–','æ± ç”°ä¿<9d>å¤«','Bob','ãƒœãƒ–','ä¿<9d>å¤«','Ikeda','ã‚¤ã‚±ãƒ€','æ± ç”°','','','','Standard Bob','','http://www.underland.com/bob','http://www.costumzee.com/users/Barbaro-2770-full.gif','http://www.underland.com','bob@underland.com',1,'male','1999-09-09','some zone','de','1-81-234-234234234',1,'456 underland ct.','2013-08-21 18:16:09'),(5,2,'Shopping','Bob Ikeda','ã‚¤ã‚±ãƒ€ãƒœãƒ–','æ± ç”°ä¿<9d>å¤«','Bob','ãƒœãƒ–','ä¿<9d>å¤«','Ikeda','ã‚¤ã‚±ãƒ€','æ± ç”°','','','','Shopping Bob','','http://www.underland.com/bob','http://www.costumzee.com/users/Barbaro-2770-full.gif','http://www.underland.com','bob@underland.com',1,'male','1999-09-09','some zone','some locale','1-81-234-234234234',1,'456 underland ct.','2013-08-21 18:16:09');
/*!40000 ALTER TABLE `personas` ENABLE KEYS */;
UNLOCK TABLES;


DROP TABLE IF EXISTS `sites`;
CREATE TABLE `sites` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `persona_id` int(11) NOT NULL,
  `url` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_sites_on_account_id_and_url` (`account_id`,`url`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

DROP TABLE IF EXISTS `tokens`;
CREATE TABLE `tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `token` varchar(512) NOT NULL,
  `token_type` tinyint(4) DEFAULT '1',
  `client` varchar(255) NOT NULL,
  `details` text,
  `issued_at` datetime NOT NULL,
  `expiration_at` datetime NOT NULL,
  `info` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_tokens_on_token` (`token`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
