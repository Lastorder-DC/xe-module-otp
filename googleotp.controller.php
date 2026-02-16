<?php
class googleotpController extends googleotp
{
	function init()
	{
	}

	function procGoogleotpUserConfig()
	{
		$oGoogleOTPModel = getModel('googleotp');
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");
		$member_srl = Context::get('logged_info')->member_srl;

		if(!$oGoogleOTPModel->checkUserConfig($member_srl)) {
			$otp_id = $oGoogleOTPModel->createGASecret();
			$oGoogleOTPModel->insertNewConfig($member_srl, $otp_id);
		} else {
			$user_config = $oGoogleOTPModel->getUserConfig($member_srl);
			$otp_id = $user_config->otp_id;
		}
		$test_auth_key = Context::get("test_auth_key");
		$test_auth_key = explode(" ", $test_auth_key);
	    $test_auth_key = implode("", $test_auth_key);

		$cond = new stdClass();
		$cond->srl = $member_srl;
		$cond->use = Context::get("use") === "Y" ? "Y" : "N";
		$cond->issue_type = Context::get("issue_type") ?: 'none';

		if($cond->use == 'Y' && !in_array($cond->issue_type, array('otp', 'email', 'sms'))) {
			return $this->createObject(-1, "2차 인증 방식을 선택해주세요.");
		}

		if($cond->use == 'Y' && $cond->issue_type == 'otp') {
			if(!$test_auth_key) {
				return $this->createObject(-1, "확인용 인증코드를 입력해주세요.");
			}

			if(!$oGoogleOTPModel->checkGAOTPNumber($otp_id, $test_auth_key)) {
				return $this->createObject(-1, "확인용 인증코드가 잘못되었습니다.");
			}
		}

		$output = executeQuery('googleotp.updateGoogleotpuserconfigbySrl', $cond);
		if(!$output->toBool()) return $this->createObject(-1, "ERROR #1 : 관리자에게 문의하세요.");

		if($cond->use === "Y")
		{
			$_SESSION['googleotp_passed'] = TRUE;
		}

		// alert a message
		if(Context::get('xeVirtualRequestMethod') !== 'xml')
		{
			$this->setMessage('success_updated');
			$this->setRedirectUrl(Context::get('error_return_url') ?: getNotEncodedUrl('', 'act', 'dispGoogleotpUserConfig'));
		}
	}

	function procGoogleotpInputotp()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1,"로그인하지 않았습니다.");
		if($_SESSION['googleotp_passed']) return $this->createObject(-1,"이미 인증했습니다.");

		$config = $this->getConfig();
		if ( $config->use_captcha === 'Y' )
		{
			$spamfilter_config = ModuleModel::getModuleConfig('spamfilter');
			$logged_info = Context::get('logged_info');
			if (
				$config->use_captcha == 'Y'
				&& isset($spamfilter_config) && isset($spamfilter_config->captcha)
				&& $spamfilter_config->captcha->type === 'recaptcha'
				&& $logged_info->is_admin !== 'Y'
			)
			{
				include_once RX_BASEDIR . 'modules/spamfilter/spamfilter.lib.php';
				spamfilter_reCAPTCHA::init($spamfilter_config->captcha);
				spamfilter_reCAPTCHA::check();
			}
		}
		
		$otpnumber = Context::get("otpinput");
		
		// change 111 111 to 111111
	    $otpnumber = explode(" ",$otpnumber);
	    $otpnumber = implode("",$otpnumber);

		if(!$otpnumber) return $this->createObject(-1,"인증번호를 입력해주세요.");
	    
		$member_srl = Context::get('logged_info')->member_srl;

		$oGoogleOTPModel = getModel('googleotp');
		$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);
		$issue_type = $userconfig->issue_type;
		
		if($oGoogleOTPModel->checkOTPNumber($member_srl,$otpnumber))
		{
		    if(!$oGoogleOTPModel->checkUsedNumber($member_srl,$otpnumber))
		    {
		        return $this->createObject(-1,"이미 인증에 사용된 번호입니다. 다른 번호를 사용해주세요.");
		    }
		    else
		    {
		        $oGoogleOTPModel->insertAuthlog($member_srl, $otpnumber, "Y", $issue_type);
			    $_SESSION['googleotp_passed'] = TRUE;

			    // 신뢰할 수 있는 기기 등록 처리
			    $trust_device = Context::get("trust_device");
			    if($trust_device === 'Y' && $config->use_trusted_device === 'Y')
			    {
			        $trust_days = intval($config->trusted_device_duration) ?: 30;
			        $device_token = $oGoogleOTPModel->registerTrustedDevice($member_srl, $trust_days);
			        if($device_token)
			        {
			            $cookie_expire = time() + ($trust_days * 86400);
			            setcookie('googleotp_trusted_device', $device_token, $cookie_expire, '/');
			        }
			    }

			    $this->setRedirectUrl($_SESSION['beforeaddress']);
		    }
		}
		else
		{
		    $oGoogleOTPModel->insertAuthlog($member_srl, $otpnumber, "N", $issue_type);
			$this->setError(-1);
			$this->setMessage("잘못된 인증 번호입니다");
			$this->setRedirectUrl(Context::get('error_return_url') ?: getNotEncodedUrl('', 'act', 'dispGoogleotpInputotp'));
		}
	}

	function procGoogleotpResendauthmessage()
	{
		Context::setResponseMethod('JSON');
		if($_SESSION['googleotp_passed']) return $this->createObject(-1,"이미 인증했습니다.");

		$member_srl = Context::get('member_srl');
		$oGoogleOTPModel = getModel('googleotp');
		$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);

		if($userconfig->issue_type == 'email')
		{
			if($oGoogleOTPModel->AvailableToSendEmail($member_srl)) // 인증 메일을 보낼 수 있을 경우
			{
				$result = $oGoogleOTPModel->sendAuthEmail($member_srl, rand(100000, 999999));
				return $this->createObject(0, "인증 메일을 재발송했습니다.");
			}
			else
			{
				return $this->createObject(-1, "인증 메일을 재발송할 수 없습니다.\n\n관리자에게 문의하세요.");
			}
		}
		elseif($userconfig->issue_type == 'sms')
		{
			if($oGoogleOTPModel->AvailableToSendSMS($member_srl)) // 인증 SMS를 보낼 수 있을 경우
			{
				$result = $oGoogleOTPModel->sendAuthSMS($member_srl, rand(100000, 999999));
				return $this->createObject(0, "인증 문자를 재발송했습니다.");
			}
			else
			{
				return $this->createObject(-1, "인증 문자를 재발송할 수 없습니다.\n\n관리자에게 문의하세요.");
			}
		}
	}

	function triggerAddMemberMenu()
	{
		$logged_info = Context::get('logged_info');
		if(!Context::get('is_logged')) return $this->createObject();

		$oMemberController = getController('member');
		$oMemberController->addMemberMenu('dispGoogleotpUserConfig', "로그인 2차 인증 설정");
		if($logged_info->is_admin== 'Y')
		{
			$target_srl = Context::get('target_srl');

			$url = getUrl('','act','dispGoogleotpUserConfig','member_srl',$target_srl);
			$oMemberController->addMemberPopupMenu($url, '유저 로그인 2차 인증 관리', '');
		}
		return $this->createObject();
	}

	function triggerHijackLogin($obj) {
		if(!Context::get("is_logged") || $obj->act === "dispMemberLogout") {
			unset($_SESSION['googleotp_passed']);
			return;
		}

		$config = $this->getConfig();
		$oGoogleOTPModel = getModel('googleotp');
		$member_srl = Context::get('logged_info')->member_srl;
		$userconfig = $oGoogleOTPModel->getUserConfig($member_srl);

		// 신뢰할 수 있는 기기 확인
		if($config->use_trusted_device === 'Y' && !$_SESSION['googleotp_passed'])
		{
			$device_token = $_COOKIE['googleotp_trusted_device'] ?? '';
			if($device_token && $oGoogleOTPModel->checkTrustedDevice($member_srl, $device_token))
			{
				$_SESSION['googleotp_passed'] = TRUE;
			}
		}

		if($userconfig->use === "Y") {
			$allowedact = array("dispGoogleotpInputotp","procGoogleotpInputotp","procMemberLogin","dispMemberLogout","procGoogleotpResendauthmessage","getMember_divideList");
			if(!in_array($obj->act, $allowedact) && !$_SESSION['googleotp_passed'])
			{
				$_SESSION['beforeaddress'] = getNotEncodedUrl();
				header("Location: " . getNotEncodedUrl('act','dispGoogleotpInputotp'));
				Context::close();
				die();
			}
		} elseif($config->force_use_otp === "Y") {
			$allowedact = array("dispGoogleotpUserConfig","procGoogleotpUserConfig","procMemberLogin","dispMemberLogout","procGoogleotpResendauthmessage","getMember_divideList");
			if(!in_array($obj->act, $allowedact) && (!$oGoogleOTPModel->checkUserConfig($member_srl) || $userconfig->use !== "Y"))
			{
				$_SESSION['beforeaddress'] = getNotEncodedUrl();
				header("Location: " . getNotEncodedUrl('act','dispGoogleotpUserConfig'));
				Context::close();
				die();
			}
		}
	}

	function triggerAutoLoginBypass($obj) {
		$config = $this->getConfig();
		if($config->bypass_auto_login === "Y") {
			$_SESSION['googleotp_passed'] = TRUE;
		}
	}

	function procGoogleotpDeleteTrustedDevice()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");

		$logged_info = Context::get('logged_info');
		$member_srl = $logged_info->member_srl;
		$idx = intval(Context::get('device_idx'));

		if(!$idx) return $this->createObject(-1, "잘못된 요청입니다.");

		$oGoogleOTPModel = getModel('googleotp');

		// 관리자는 다른 회원의 기기도 삭제 가능
		if($logged_info->is_admin === 'Y' && Context::get('target_member_srl'))
		{
			$member_srl = intval(Context::get('target_member_srl'));
		}

		if(!$oGoogleOTPModel->deleteTrustedDevice($idx, $member_srl))
		{
			return $this->createObject(-1, "기기 삭제에 실패했습니다.");
		}

		$this->setMessage('success_deleted');
		if(Context::get('success_return_url'))
		{
			$this->setRedirectUrl(Context::get('success_return_url'));
		}
		else
		{
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpTrustedDevices'));
		}
	}

	function procGoogleotpDeleteAllTrustedDevices()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");

		$logged_info = Context::get('logged_info');
		$member_srl = $logged_info->member_srl;

		$oGoogleOTPModel = getModel('googleotp');

		// 관리자는 다른 회원의 기기도 삭제 가능
		if($logged_info->is_admin === 'Y' && Context::get('target_member_srl'))
		{
			$member_srl = intval(Context::get('target_member_srl'));
		}

		if(!$oGoogleOTPModel->deleteAllTrustedDevices($member_srl))
		{
			return $this->createObject(-1, "기기 삭제에 실패했습니다.");
		}

		// 쿠키 삭제
		setcookie('googleotp_trusted_device', '', time() - 3600, '/');

		$this->setMessage('success_deleted');
		if(Context::get('success_return_url'))
		{
			$this->setRedirectUrl(Context::get('success_return_url'));
		}
		else
		{
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpTrustedDevices'));
		}
	}
}
