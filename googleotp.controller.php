<?php
class googleotpController extends googleotp
{
	function init()
	{
	}

	function procGoogleotpUserConfig()
	{
		if(!Context::get("is_logged")) return new Object(-1,"로그인해주세요");

		$oGoogleOTPModel = getModel('googleotp');

		if(!$oGoogleOTPModel->checkUserConfig(Context::get('logged_info')->member_srl)) {
			$oGoogleOTPModel->insertNewConfig(Context::get('logged_info')->member_srl);
		}

		$cond = new stdClass();
		$cond->srl=Context::get('logged_info')->member_srl;
		$cond->use = Context::get("use") === "Y" ? "Y" : "N";
		$output = executeQuery('googleotp.updateGoogleotpuserconfigbySrl', $cond);
		if(!$output->toBool()) return new Object(-1,"ERROR");

		if($cond->use === "Y")
		{
			$_SESSION['googleotp_passed'] = TRUE;
		}

		// alert a message
		if(Context::get('xeVirtualRequestMethod') !== 'xml')
		{
			$this->setMessage('success_updated');
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpUserConfig'));
		}
	}

	function procGoogleotpInputotp()
	{
		if(!Context::get("is_logged")) return new Object(-1,"로그인하지 않았습니다.");
		if($_SESSION['googleotp_passed']) return new Object(-1,"이미 인증했습니다.");

		$oGoogleOTPModel = getModel('googleotp');
		if($oGoogleOTPModel->checkOTPNumber(Context::get('logged_info')->member_srl,Context::get("otpinput")))
		{
			$_SESSION['googleotp_passed'] = TRUE;
			$this->setRedirectUrl($_SESSION['beforeaddress']);
		}
		else
		{
			$this->setMessage("잘못된 OTP 번호입니다");
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpInputotp'));
		}
	}

	function triggerAddMemberMenu()
	{
		$logged_info = Context::get('logged_info');
		if(!Context::get('is_logged')) return new Object();

		$oMemberController = getController('member');
		$oMemberController->addMemberMenu('dispGoogleotpUserConfig', "OTP 설정");
		if($logged_info->is_admin== 'Y')
		{
			$target_srl = Context::get('target_srl');

			$url = getUrl('','act','dispGoogleotpUserConfig','member_srl',$target_srl);
			$oMemberController->addMemberPopupMenu($url, '유저 OTP 설정', '');
		}
		return new Object();
	}

	function triggerHijackLogin(&$obj) {
		if(!Context::get("is_logged") || $obj->act === "dispMemberLogout") {
			unset($_SESSION['googleotp_passed']);
			return;
		}

		$oGoogleOTPModel = getModel('googleotp');
		$userconfig = $oGoogleOTPModel->getUserConfig(Context::get('logged_info')->member_srl);
		if($userconfig->use === "Y") {
			$allowedact = array("dispGoogleotpInputotp","procGoogleotpInputotp","procMemberLogin","dispMemberLogout");
			if(!in_array($obj->act,$allowedact) && !$_SESSION['googleotp_passed'])
			{
				$_SESSION['beforeaddress'] = getNotEncodedUrl();
				header("Location: " . getNotEncodedUrl('act','dispGoogleotpInputotp'));
				Context::close();
				die();
			}
		}
	}
}
