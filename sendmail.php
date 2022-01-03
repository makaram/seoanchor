<?php 

        //$_POST['g-recaptcha-response'])
          $captcha=$_POST['g-recaptcha-response'];
          if(!empty($captcha)){
              //echo "capta is present";
              $secretKey = "6LfMQz0dAAAAAMrdn96-9SRgXuiliUezQsYMYX-m";
              $ip = $_SERVER['REMOTE_ADDR'];
              $url = 'https://www.google.com/recaptcha/api/siteverify?secret=' . urlencode($secretKey) .  '&response=' . urlencode($captcha);
              $response = file_get_contents($url);
            $responseKeys = json_decode($response,true);
            if($responseKeys["success"]) {
                	$name = trim($_POST['name']);
	$email = $_POST['email'];
	$comments = $_POST['comments'];
	
	$site_owners_email = 'dev.m@seoanchor.net'; // Replace this with your own email address
	$site_owners_name = 'M.Tayyab'; // replace with your name
	
	if (strlen($name) < 2) {
		$error['name'] = "Please enter your name";	
	}
	
	if (!preg_match('/^[a-z0-9&\'\.\-_\+]+@[a-z0-9\-]+\.([a-z0-9\-]+\.)*+[a-z]{2}/is', $email)) {
		$error['email'] = "Please enter a valid email address";	
	}
	
	if (strlen($comments) < 3) {
		$error['comments'] = "Please leave a comment.";
	}
	
	if (!$error) {
		
		require_once('phpMailer/class.phpmailer.php');
		$mail = new PHPMailer();
		$mail->From = $email;
		$mail->FromName = $name;
		$mail->Subject = "Contact Form";
		$mail->AddAddress($site_owners_email, $site_owners_name);
		$mail->IsHTML(true);
		$mail->Body = '<b>Name:</b> '. $name .'<br/><b>E-mail:</b> '. $email .'<br/><br/>' . $comments;
		
		$mail->Send();
		
		//echo "<div data-alert class='alert alert-success'>Thanks " . $name . ". Your message has been sent.<a href='#' class='close' onclick='clearForms()'>&times;</a></div>";
		echo '<div class="alert alert-success col-6 offset-2" role="alert">
  Thanks '  . $name .' Your message has been sent. <button type="button" class="btn-close offset-2" data-bs-dismiss="alert" aria-label="Close"></button>
</div>';
	} # end if no error
	else {

		$response = (isset($error['name'])) ? "<div class='alert alert-danger col-6 offset-2'>" . $error['name'] . "</div> \n" : null;
		$response .= (isset($error['email'])) ? "<div class='alert alert-danger col-6 offset-2'>" . $error['email'] . "</div> \n" : null;
		$response .= (isset($error['comments'])) ? "<div class='alert alert-danger col-6 offset-2'>" . $error['comments'] . "</div>" : null;
		
		echo $response;
		
	} # end if there was an error sending

        }
        else{echo '<div class="alert alert-danger col-6 offset-2" role="alert">
  Recaptcha is Invalid <button type="button" class="btn-close offset-2" data-bs-dismiss="alert" aria-label="Close"></button>
</div>';}
          }
          else {
              echo '<div class="alert alert-danger col-6 offset-2" role="alert">
  Recaptcha is missing <button type="button" class="btn-close offset-2" data-bs-dismiss="alert" aria-label="Close"></button>
</div>';
          }
        
        
        //$secretKey = "Put your secret key here";
        //$ip = $_SERVER['REMOTE_ADDR'];
        // post request to server
        //$url = 'https://www.google.com/recaptcha/api/siteverify?secret=' . urlencode($secretKey) .  '&response=' . urlencode($captcha);
        //$response = file_get_contents($url);
        //$responseKeys = json_decode($response,true);
        //// should return JSON with success as true
        //if($responseKeys["success"]) {
          //      echo '
//Thanks for posting comment
//';
  //      } else {
    //            echo '
//You are spammer ! Get the @$%K out
//';
  //      }
?>