<?php
use voku\helper\HtmlDomParser;
require_once 'vendor/autoload.php';
$error = "";
$domain = "";
$pattern = "^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$^";
              
    $domain = $_POST['domain'];
    $ch = curl_init($domain);
      curl_setopt($ch, CURLOPT_HEADER, true);    // we want headers
      curl_setopt($ch, CURLOPT_NOBODY, true);    // we don't need body
      //curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($ch, CURLOPT_TIMEOUT, 10);
      $output = curl_exec($ch);
      $info = curl_getinfo($ch);
      //echo "Status Code is".."<br>";
      //echo  $info["size_download"];
      $statuscode = $info["http_code"];

      //echo '<pre>';
      //var_dump($info, $output);
      curl_close($ch);
      $ch1 = curl_init($domain);
      curl_setopt($ch1, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($ch1, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($ch1, CURLOPT_SSL_VERIFYHOST, false);
      curl_setopt($ch1, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($ch1, CURLOPT_HTTPHEADER, [
        'accept: application/json, text/plain, */*',
        'Accept-Language: en-US,en;q=0.5',
        'x-application-type: WebClient',
        'x-client-version: 2.10.4',
        'Origin: https://www.googe.com',
        'user-agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
      ]);
      curl_setopt($ch1, CURLOPT_TIMEOUT, 10);
      $output = curl_exec($ch1);
      $info = curl_getinfo($ch1);
      $fsize = $info["size_download"];
      $redirectedUrl = $info["url"];
      //echo '<pre>';
      //var_dump($info, $output);
      //$redirectedUrl = curl_getinfo($ch1, CURLINFO_EFFECTIVE_URL);

      curl_close($ch1);
      
    if(!empty($domain)){
      
        if (strpos($domain, "http://") === 0) {
            $domain = $domain;
          } elseif (strpos($domain, "https://") === 0) {
            $domain = $domain;
          } elseif (strpos($domain, "http://") !== 0 && strpos($domain, "https://") !== 0) {
            $domain = "http://" . $domain;
          }
          if (strpos($domain, "www.") == !false) {
            $trimmed_url = explode('//', $redirectedUrl)[1];
            $trimmed_url = trim($trimmed_url, "/");
            $trimmed_url = explode('www.', $trimmed_url)[1];
          } else {
            $trimmed_url = explode('//', $redirectedUrl)[1];
            $trimmed_url = trim($trimmed_url, "/");
          }      
        
      $head_info = curl_init($domain);
      curl_setopt($head_info, CURLOPT_HEADER, true);    // we want headers
      curl_setopt($head_info, CURLOPT_NOBODY, true);    // we don't need body
      curl_setopt($head_info, CURLOPT_FOLLOWLOCATION, true);
      curl_setopt($head_info, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($head_info, CURLOPT_TIMEOUT, 10);
      $head_details = curl_exec($head_info);
      curl_close($head_info);
      $curl = curl_init($redirectedUrl);
      curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($curl, CURLOPT_TIMEOUT, 10);
      $in = curl_getinfo($curl);
      $http_version = $info["http_version"];
      curl_close($curl);
      $parse = parse_url($domain);

      // Default doms if not parameters
      $doms = ['apple.com', 'microsoft.com', 'google.com', $parse['host']];


      // Clean the input
      $doms = array_filter($doms, function ($dom) {
        return $dom !== '';
      });

      $doms = array_filter($doms, function ($dom) {
        return strpos($dom, '.') > 0;
      });

      $doms = array_unique($doms);

      // Get maximum of 5 dom per request
      $doms = array_slice($doms, 0, 5);

      // Get certificate info
      // This code is adopted from http://stackoverflow.com/a/29779341/967802
      function getCertificate($dom)
      {
        $url = "https://$dom";
        $orignal_parse = parse_url($url, PHP_URL_HOST);
        $get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));
        $read = stream_socket_client("ssl://" . $orignal_parse . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);
        $cert = stream_context_get_params($read);
        $certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
        return $certinfo;
      }

      // Process ceriticate info of each dom
      $certs = [];
      foreach ($doms as $dom) {
        $rawCert = getCertificate($dom);
        $cert = [];
        $cert['domain'] = $dom;
        $cert['serialNumber'] = $rawCert['serialNumber'];
        $cert['validFrom'] = gmdate("Y-m-d\TH:i:s\Z", $rawCert['validFrom_time_t']);
        $cert['validTo'] = gmdate("Y-m-d\TH:i:s\Z", $rawCert['validTo_time_t']);
        $cert['validToUnix'] = $rawCert['validTo_time_t'];
        $cert['issuer'] = $rawCert['issuer']['CN'];
        $cert['days'] = (intval($cert['validToUnix']) - time()) / 60 / 60 / 24;
        $certs[] = $cert;
      }

      // Sort by expiring time
      $validTo = array();
      foreach ($certs as $key => $row) {
        $validTo[$key] = $row['validToUnix'];
      }
      array_multisort($validTo, SORT_ASC, $certs);
      $dcurl = curl_init();
    // Use Curl to send off your request.
    // Send your encoded list of domains through Curl's POSTFIELDS.
   curl_setopt_array($dcurl, array(
  CURLOPT_URL => 'https://lsapi.seomoz.com/v2/url_metrics',
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_ENCODING => '',
  CURLOPT_MAXREDIRS => 10,
  CURLOPT_TIMEOUT => 0,
  CURLOPT_FOLLOWLOCATION => true,
  CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
  CURLOPT_CUSTOMREQUEST => 'POST',
  CURLOPT_POSTFIELDS =>'{
    "targets": ["'.$domain.'"]
}',
  CURLOPT_HTTPHEADER => array(
    'Authorization: Basic bW96c2NhcGUtMTUwOWM4MjY4MzphMTk0Yjc3NjAxMWU5Y2YwYWY4MzkyY2Y2ZTYyNDdjYQ==',
    'Content-Type: text/plain',
    'Cookie: __cf_bm=RGOs8K4_ts39MV0E6C6qJnoXzhlIB6.ASfY.MeeHLOo-1635958710-0-AU+fGqXvMliZKWGuqbO3f+s3Fcs6aGwvfUbyFqct1lGlOKX7qHAJddxv4oR2e3po7OTRUpv8/tgx54t79xnvEoQ='
  ),
));

  $response = curl_exec($dcurl);

curl_close($dcurl);
    $contents = json_decode($response,true);
 $page_authority =$contents['results'][0]['page_authority'];
    $domain_authority =$contents['results'][0]['domain_authority'];
       $spam_score=$contents['results'][0]['spam_score'];

      try {
        $html = HtmlDomParser::str_get_html($output);
        $code_length =  strlen($html->outerhtml);
        $text_length = strlen($html->plaintext);
        $script = $html->find('script');
        $iframe = $html->find('iframe');
        count($iframe);
        foreach ($script as $schema) {
          if ($schema->hasAttribute('type')) {
            $schema_data[$schema->getAttribute('type')][] = $schema->plaintext;
          }
        }
        if (isset($schema_data['application/ld+json']))
          $schema = $schema_data['application/ld+json'][0];
        else $schema = "Schema Not Found";
        $links = $html->find('link');
        //print_r($link);
        foreach ($links as $link)
          //var_dump($link->hasAttribute('rel'), $link->getAttribute('href'));
          //var_dump($link->hasAttribute('rel'),$link->getAttribute('rel'));
          if ($link->hasAttribute('rel')) {
            $link_data[$link->getAttribute('rel')][] = $link->getAttribute('href');
            // print_r($link_data);

          }
        //$script = $html->find('script');
          
    $canonical = "";
    if (isset($link_data['icon']))
      $favicon = $link_data['icon'];
    //count($favicon);
    elseif (isset($link_data['shortcut icon'])) {
      $favicon = $link_data['shortcut icon'];
    }
    //print_r($favicon);
    if (isset($link_data['canonical'])) {
      $canonical = $link_data['canonical'];
    }
      } catch (Exception $e) {
        var_dump($e);
      }
      try {
        //$html = HtmlDomParser::str_get_html($output);
        foreach ($html->find('meta') as $meta) {
          if ($meta->hasAttribute('content')) {
            $meta_data[$meta->getAttribute('name')][] = $meta->getAttribute('content');
          }

          if ($meta->hasAttribute('charset')) {
            $charset = $meta->getAttribute('charset');
          }
          if ($meta->hasAttribute('property')) {
            $og_data[$meta->getAttribute('property')][] = $meta->getAttribute('content');
          }
        }
        //var_dump($og_data);
        // dump contents
        /** @noinspection ForgottenDebugOutputInspection */
        //var_export($meta_data, false);
        if (isset($meta_data['keywords']))
          $keywords = $meta_data['keywords'];
        else
          $keywords[0] = "Keywords Not Found";
        if (isset($meta_data['description']))
          $desc = $meta_data['description'];
        else $desc[0] = " Desription not found";
        //$desc_check = count($meta_data['description']);
        //echo($meta_data['description'][0]);
        //echo count( $html->find('title') ); 

      } catch (Exception $e) {
        var_dump((string)$e);
      }
     
    class DomainAge
    {
      private $WHOIS_SERVERS = array(
        "com"               =>  array("whois.verisign-grs.com", "/Creation Date:(.*)/"),
        "net"               =>  array("whois.verisign-grs.com", "/Creation Date:(.*)/"),
        "org"               =>  array("whois.pir.org", "/Creation Date:(.*)/"),
        "info"              =>  array("whois.afilias.info", "/Created On:(.*)/"),
        "biz"               =>  array("whois.neulevel.biz", "/Creation Date:(.*)/"),
        "us"                =>  array("whois.nic.us", "/Domain Registration Date:(.*)/"),
        "uk"                =>  array("whois.nic.uk", "/Registered on:(.*)/"),
        "ca"                =>  array("whois.cira.ca", "/Creation date:(.*)/"),
        "tel"               =>  array("whois.nic.tel", "/Domain Registration Date:(.*)/"),
        "ie"                =>  array("whois.iedr.ie", "/registration:(.*)/"),
        "it"                =>  array("whois.nic.it", "/Created:(.*)/"),
        "cc"                =>  array("whois.nic.cc", "/Creation Date:(.*)/"),
        "ws"                =>  array("whois.nic.ws", "/Domain Created:(.*)/"),
        "sc"                =>  array("whois2.afilias-grs.net", "/Created On:(.*)/"),
        "mobi"              =>  array("whois.dotmobiregistry.net", "/Created On:(.*)/"),
        "pro"               =>  array("whois.registrypro.pro", "/Created On:(.*)/"),
        "edu"               =>  array("whois.educause.net", "/Domain record activated:(.*)/"),
        "tv"                =>  array("whois.nic.tv", "/Creation Date:(.*)/"),
        "travel"            =>  array("whois.nic.travel", "/Domain Registration Date:(.*)/"),
        "in"                =>  array("whois.inregistry.net", "/Created On:(.*)/"),
        "me"                =>  array("whois.nic.me", "/Domain Create Date:(.*)/"),
        "cn"                =>  array("whois.cnnic.cn", "/Registration Date:(.*)/"),
        "asia"              =>  array("whois.nic.asia", "/Domain Create Date:(.*)/"),
        "ro"                =>  array("whois.rotld.ro", "/Registered On:(.*)/"),
        "aero"              =>  array("whois.aero", "/Created On:(.*)/"),
        "nu"                =>  array("whois.nic.nu", "/created:(.*)/"),

      );
      public function age($domain)
      {
        $domain = trim($domain); //remove space from start and end of domain
        if (substr(strtolower($domain), 0, 7) == "http://") $domain = substr($domain, 7); // remove http:// if included
        if (substr(strtolower($domain), 0, 4) == "www.") $domain = substr($domain, 4); //remove www from domain
        if (preg_match("/^([-a-z0-9]{2,100})\.([a-z\.]{2,8})$/i", $domain)) {
          $ex = substr_count($domain, ".");
          $domain_parts = explode(".", $domain);

          $tld = strtolower(array_pop($domain_parts));
          if (!$server = $this->WHOIS_SERVERS[$tld][0]) {
            return false;
          }
          $res = $this->queryWhois($server, $domain);
          if (preg_match($this->WHOIS_SERVERS[$tld][1], $res, $match)) {
            date_default_timezone_set('UTC');
            $time = time() - strtotime($match[1]);
            $years = floor($time / 31556926);
            $days = floor(($time % 31556926) / 86400);
            if ($years == "1") {
              $y = "1 year";
            } else {
              $y = $years . " years";
            }
            if ($days == "1") {
              $d = "1 day";
            } else {
              $d = $days . " days";
            }
            return "$y, $d";
          } else
            return false;
        } else
          return false;
      }
      private function queryWhois($server, $domain)
      {
        $fp = @fsockopen($server, 43, $errno, $errstr, 20) or die("Socket Error " . $errno . " - " . $errstr);
        if ($server == "whois.verisign-grs.com")
          $domain = "=" . $domain;
        fputs($fp, $domain . "\r\n");
        $out = "";
        while (!feof($fp)) {
          $out .= fgets($fp);
        }
        fclose($fp);
        return $out;
      }
    }

    $anchor = $html->find('a');
      foreach ($anchor as $a) {
        $href = $a->getAttribute('href');
        if (strpos($redirectedUrl, "://") !== false || strpos($redirectedUrl, "//") === 0) {
          if (strpos($redirectedUrl, "www.") == !false) {
            $trimmed_url = explode('//', $redirectedUrl)[1];
            $trimmed_url = trim($trimmed_url, "/");
            $trimmed_url = explode('www.', $trimmed_url)[1];
          } else {
            $trimmed_url = explode('//', $redirectedUrl)[1];
            $trimmed_url = trim($trimmed_url, "/");
          }
          $domain_name = explode(".", $trimmed_url)[0];
          //echo $trimmed_url;
        }
        if ($a->hasAttribute('href') && !empty($href) && strpos($href, "#") === false) {
          $href1 = trim($href);
          //$is_internal = true;
          if ($href !== '' && (strpos($href, '://') !== false || strpos($href, '//') === 0)) {
            if (strpos($href1, '://') !== false) {
              $href1 = explode('://', $href)[1];
            }
            $href1 = trim($href1, '/');

            if (strpos($href1, '/') !== false) {
              $href1 = explode('/', $href1)[0];
            }

            if (strpos($href1, 'www.') === 0) {
              $href1 = explode('www.', $href1)[1];
            }

            if ($href1 != $trimmed_url) {
              $external_href[] = $href;
              $external_html[] = $a->innerhtml;
            } else
              $internal_href[] = $href;
            $internal_html[] = $a->innerhtml;
          } else {
            $internal_href[] = $href;
            $internal_html[] = $a->innerhtml;
          }
        }
      }
      $category = '&category=performance&category=seo&category=best-practices';
    $strategy = '&strategy=desktop';
    $api_key  = '&key=AIzaSyCR1tsZLGqG3j3ui7EikxdJ-MJdnNn3HIw';

    $new_url = $domain . $category . $strategy . $api_key;

    $url     = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=' . $new_url;

    $ch_desktop      = curl_init();
    curl_setopt($ch_desktop, CURLOPT_URL, $url);
    curl_setopt($ch_desktop, CURLOPT_HEADER, 1);
    curl_setopt($ch_desktop, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch_desktop, CURLOPT_HEADER, false);
    $data_desktop = curl_exec($ch_desktop);
    curl_close($ch_desktop);

    $decoded_data = json_decode($data_desktop, true);
    //print_r($decoded_data);
    $response_desktop = [];

    if (isset($decoded_data['lighthouseResult'])) {
      $result = $decoded_data['lighthouseResult'];

      $response_desktop['requested_url'] = isset($result['requestedUrl']) ? $result['requestedUrl'] : '';
      $response_desktop['final_url']     = isset($result['finalUrl']) ? $result['finalUrl'] : '';

      $audits         = $result['audits'];
      $response_desktop['lcp'] = $audits['largest-contentful-paint']['displayValue'];
      $response_desktop['lcp_nv'] = $audits['largest-contentful-paint']['numericValue'];
      $response_desktop['si'] = $audits['speed-index']['displayValue'];
      $response_desktop['si_nv'] = $audits['speed-index']['numericValue'];
      $response_desktop['ti'] = $audits['interactive']['displayValue'];
      $response_desktop['ti_nv'] = $audits['interactive']['numericValue'];
      $response_desktop['tbl'] = $audits['total-blocking-time']['displayValue'];
      $response_desktop['tbl_nv'] = $audits['total-blocking-time']['numericValue'];
      $response_desktop['fcp'] = $audits['first-contentful-paint']['displayValue'];
      $response_desktop['fcp_nv'] = $audits['first-contentful-paint']['numericValue'];
      $performance    = isset($result['categories']['performance']['score']) ? $result['categories']['performance']['score'] : 0;  //0.74
      $seo_audit_refs = isset($result['categories']['seo']['auditRefs']) ? $result['categories']['seo']['auditRefs'] : [];         //array
      $response_desktop['page_score'] = $performance * 100;
      $encoded_screenshot = $audits['final-screenshot']['details']['data'];
      $response_desktop['screenshot'] = str_replace(array('_', '-'), array('/', '+'), $encoded_screenshot);
      $response_desktop['cls'] = $audits['cumulative-layout-shift']['displayValue'];
      //security
      $vulnerable_libraries_score = $audits['no-vulnerable-libraries']['score'];

      $best_practice_auditrefs = isset($result['categories']['best-practices']['auditRefs']) ? $result['categories']['best-practices']['auditRefs'] : [];
      $https_weight = 0;
      foreach ($best_practice_auditrefs as $ref) {
        if ($ref['id'] == 'is-on-https') {
          $https_weight = $ref['weight'];
          break;
        }
      }
      $response_desktop['is_https'] = $https_weight;
      $response_desktop['vulnerable_libraries'] = $vulnerable_libraries_score;
    }

    //var_dump($response_desktop);

    $category = '&category=performance&category=seo&category=best-practices';
    $strategy = '&strategy=mobile';
    $api_key  = '&key=AIzaSyCR1tsZLGqG3j3ui7EikxdJ-MJdnNn3HIw';

    $new_url = $domain . $category . $strategy . $api_key;

    $url     = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=' . $new_url;

    $ch_mobile      = curl_init();
    curl_setopt($ch_mobile, CURLOPT_URL, $url);
    curl_setopt($ch_mobile, CURLOPT_HEADER, 1);
    curl_setopt($ch_mobile, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch_mobile, CURLOPT_HEADER, false);
    $data_mobile = curl_exec($ch_mobile);
    curl_close($ch_mobile);

    $decoded_data = json_decode($data_mobile, true);
    //print_r($decoded_data);
    $response_mobile = [];

    if (isset($decoded_data['lighthouseResult'])) {
      $result = $decoded_data['lighthouseResult'];

      $response_mobile['requested_url'] = isset($result['requestedUrl']) ? $result['requestedUrl'] : '';
      $response_mobile['final_url']     = isset($result['finalUrl']) ? $result['finalUrl'] : '';
      $audits         = $result['audits'];
      $performance    = isset($result['categories']['performance']['score']) ? $result['categories']['performance']['score'] : 0;  //0.74
      $seo_audit_refs = isset($result['categories']['seo']['auditRefs']) ? $result['categories']['seo']['auditRefs'] : [];         //array

      $response_mobile['page_score'] = $performance * 100;

      $encoded_screenshot = $audits['final-screenshot']['details']['data'];
      $response_mobile['screenshot'] = str_replace(array('_', '-'), array('/', '+'), $encoded_screenshot);

      $response_mobile['lcp'] = $audits['largest-contentful-paint']['displayValue'];
      $response_mobile['lcp_nv'] = $audits['largest-contentful-paint']['numericValue'];
      $response_mobile['si'] = $audits['speed-index']['displayValue'];
      $response_mobile['si_nv'] = $audits['speed-index']['numericValue'];
      $response_mobile['ti'] = $audits['interactive']['displayValue'];
      $response_mobile['ti_nv'] = $audits['interactive']['numericValue'];
      $response_mobile['tbl'] = $audits['total-blocking-time']['displayValue'];
      $response_mobile['tbl_nv'] = $audits['total-blocking-time']['numericValue'];
      $response_mobile['fcp'] = $audits['first-contentful-paint']['displayValue'];
      $response_mobile['fcp_nv'] = $audits['first-contentful-paint']['numericValue'];
      $response_mobile['cls'] = $audits['cumulative-layout-shift']['displayValue'];
      //security
      $vulnerable_libraries_score = $audits['no-vulnerable-libraries']['score'];

      $best_practice_auditrefs = isset($result['categories']['best-practices']['auditRefs']) ? $result['categories']['best-practices']['auditRefs'] : [];
      $https_weight = 0;
      foreach ($best_practice_auditrefs as $ref) {
        if ($ref['id'] == 'is-on-https') {
          $https_weight = $ref['weight'];
          break;
        }
      }
      $response_mobile['is_https'] = $https_weight;
      $response_mobile['vulnerable_libraries'] = $vulnerable_libraries_score;
    }
   
   
}
    else {
        $error = "PLease  Enter The  Domain Name ";
    }
if(isset($_POST['domain']) && empty($error))
{
  echo "<div class='output bg-light canvas_div_pdf' id = 'pdf'>
  <h2 class='text-dark text-center py-3'> Page Analysis Report for ".$trimmed_url." </h2>
  <div class='border border-5 py-0 my-0'>
  <h3 class='bg-secondary text-white-50 px-2 py-3'> On Page SEO Report</h3>
  <div class='row mx-3 border-bottom '>
  <div class='col-2'>
  <p><strong>
  Status Code:</strong>
  </p></div>
  <div class='col-10'>
  ";
  
          if ($statuscode == 200) {
            echo '<p class ="text-success">' . $statuscode . '<i class="ml-5 bi bi-check-circle-fill"></i> </p>';
          } elseif ($statuscode == 301) {
            echo '<p class ="text-warning">' . $statuscode . '-><span class ="text-success">200</span><i class="ml-5 bi bi-exclamation-circle-fill"></i> </p>';
          } elseif ( $statuscode == 302) {
            echo '<p class ="text-warning">' . $statuscode . '-><span class ="text-success">200</span><i class="ml-5 bi bi-exclamation-circle-fill"></i></p>';
          }
          elseif ($statuscode == 303) {
            echo '<p class ="text-warning">' . $statuscode . '-><span class ="text-success">200</span><i class="ml-5 bi bi-exclamation-circle-fill"></i> </p>';
          } elseif ( $statuscode == 304) {
            echo '<p class ="text-warning">' . $statuscode . '-><span class ="text-success">200</span><i class="ml-5 bi bi-exclamation-circle-fill"></i></p>';
          }
          elseif ($statuscode == 305) {
            echo '<p class ="text-warning">' . $statuscode . '-><span class ="text-success">200</span><i class="ml-5 bi bi-exclamation-circle-fill"></i> </p>';
          } elseif ( $statuscode == 306) {
            echo '<p class ="text-warning">' . $statuscode . '-><span class ="text-success">200</span><i class="ml-5 bi bi-exclamation-circle-fill"></i></p>';
          }
          elseif ($statuscode == 307) {
            echo '<p class ="text-warning">' . $statuscode . '-><span class ="text-success">200</span><i class="ml-5 bi bi-exclamation-circle-fill"></i> </p>';
          } elseif ( $statuscode == 308) {
            echo '<p class ="text-warning">' . $statuscode . '-><span class ="text-success">200</span><i class="ml-5 bi bi-exclamation-circle-fill"></i></p>';
          }
          elseif ($statuscode == 404) {
            echo '<p class ="text-danger">' . $statuscode . '<i class="ml-5 bi bi-x-circle-fill"></i></p>';
          } elseif ( $statuscode == 0) {
            echo '<p class ="text-danger">No Http Code found <i class="ml-5 bi bi-x-circle-fill"></i></p>';
          }
 
echo'
<div class="accordion" id="accordionExample">
  <div class="accordion-item">
    <h2 class="accordion-header" id="headingOne">
      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne" aria-expanded="true" aria-controls="collapseOne">
          Details
      </button>
    </h2>
    <div id="collapseOne" class="accordion-collapse collapse show" aria-labelledby="headingOne" data-bs-parent="#accordionExample">
      <div class="accordion-body">
<pre>'.($head_details).'</pre>
        
</div>
</div>
</div>

</div>
';
echo '  
</div>
</div>';
echo "<div class ='row mx-3 border-bottom'>
<div class='col-2'><p><strong>Http Version :</strong></p></div>
<div class='col-10'>"; 
if (!empty($domain) && $http_version < 3) {
  echo '<p > Your Website does not Support HTTP 2 or above version</p>';
} elseif (!empty($domain) && $http_version == 3) {
  echo '<p > Your Website does  Support HTTP 2  But does Not support HTTP 3</p>';
} elseif (!empty($domain) && $http_version > 3) {
  '<p > Your Website does  Support HTTP 3 or above version</p>';
}

echo"</div>
</div>
";
echo"<div class='row mx-3'>
<div class='col-2'><p><strong>SSL:</strong></p></div>
<div class='col-10'>";
if (!empty($cert['serialNumber'])) {
  $ssl = "<p class='text-success'>SSl Found</p>";
} else {
  $ssl = "<p class='text-danger'>SSL Not Found</p>";
}
echo $ssl;

echo"
</div>
";
if (!empty($cert['serialNumber'])) {
  echo "<div class='col-2'><p><strong>Issued By:</strong></p></div>";
  echo "<div class ='col-10'>" . $cert['issuer'] . "</div>";
} 
echo"</div>";
echo "<div class ='row mx-3 border-bottom'>
<div class='col-2'><p><strong>Html File Size :</strong></p></div>
<div class='col-10 pt-1'>";
$fsizeinkb = $fsize / 1024;
echo round($fsizeinkb) . "KB";
echo "</div></div>  ";
  echo "
   <div class='row mx-3 border-bottom'>
  <div class='col-2'><p><strong>Domain Length :</strong></p></div>
  <div class='col-10'>";
  echo $domain_name . "(" . strlen($domain_name) . "Characters)</div>";
  echo  "</div>
  <div class='row mx-3 border-bottom'>
  
  <h4>
  Title Check:
  </h4>
  
  <div class='col-6'>
  <p>";
  $title = $html->find('title');
  if(isset($title)){
  foreach ($title as $e) {

    echo  $e->innerhtml;
  }
  foreach ($title as $e) {

    //echo  ;
    $title_length = strlen($e->innertext);
  }}
  else '<span class="text-danger">Title Not Found</span>';
  echo  "
  </p>
  </div>
  <div class='col-6'>";
  if($title_length >= 35 && $title_length <= 65){
    echo "<p class ='text-success '><i class='bi bi-check-circle-fill'></i></p>";
  }
  elseif($title_length < 35){
    echo "<p class ='text-danger '><i class='bi bi-x-circle-fill'></i></p>";
  }
  elseif ($title_length >= 65 && $title_length <= 75){
    echo "<p class ='text-warning '><i class='bi bi-exclamation-circle-fill'></i></p>";
  
  }
  elseif( $title_length > 75){
    echo "<p class ='text-danger '><i class='bi bi-x-circle-fill'></i></p>";
  
  }
  echo"</div>
  </div>
  
  <div class='row mx-3 border-bottom'>
  <div class='col-2'>
  <p><strong>Title Length:</strong></p>
  </div><div class='col-10'>";
  foreach ($title as $e) {

    //echo  ;
    $title_length = strlen($e->innertext);
    if ($title_length < 35) {
      echo "<span class ='text-danger'>" . $title_length . " characters</span>";
    } elseif ($title_length >= 35 && $title_length <= 65) {
      echo "<span class ='text-success'>" . $title_length . " Characters</span>";
    } elseif ($title_length >= 65 && $title_length <= 75) {
      echo "<span class ='text-warning'>" . $title_length . " Characters</span>";
    } elseif ($title_length > 75) {
      echo "<span class ='text-danger'>" . $title_length . " Characters</span>";
    }

    echo "<br>Recommended 35-65 characters ";
  }

  echo "
  </div>
  </div>
  <div class='row mx-3 border-bottom'>
  <div class='col-2'>
  <p><strong>
  Description check:
  </strong></p>
  </div> 
  <div class='col-10'>
  ";
  if (isset($meta_data['description'])) {
    $dec_length = strlen($desc[0]);   
    foreach ($desc as $e) {
         if($dec_length< 70 )
      echo $e.'<i class="text-danger ml-5 bi bi-x-circle-fill"></i>';
      elseif($dec_length >= 70 && $dec_length <= 320)
      echo $e.'<i class="text-success ml-5 bi bi-check-circle-fill"></i>';
      elseif($dec_length >= 320 && $dec_length <= 400)
      echo $e.'<i class="text-warning ml-5 bi bi-exclamation-circle-fill"></i>';
      elseif($dec_length > 400)
      echo $e.'<i class="text-danger ml-5 bi bi-x-circle-fill"></i>';
    }
  }
  else echo "<span class ='text-danger'>Description not found</span>";
  echo "
  </div>
  </div>
  <div class='row mx-3 border-bottom'>
  <div class ='col-2'><p><strong>Description Length:</strong></p></div> 
  <div class='col-10'>";
  if(isset($meta_data['description'])){
  if ($dec_length < 70) {
    echo "<span class ='text-danger'>" . $dec_length . " characters</span>";
  } elseif ($dec_length >= 70 && $dec_length <= 320) {
    echo "<span class ='text-success'>" . $dec_length . " Characters</span>";
  } elseif ($dec_length >= 320 && $dec_length <= 400) {
    echo "<span class ='text-warning'>" . $dec_length . " Characters</span>";
  } elseif ($dec_length > 400) {
    echo "<span class ='text-danger'>" . $dec_length . " Characters</span>";
  } else
    echo "<span class='text-danger'>NO Description Found</span>";
  echo "<br>Recommended 70-320 characters ";
}
  echo "
  </div>
  </div>
  <div class='row mx-3 border-bottom '>
  <div class='col-2'>
  <p><strong>Google Preview:</strong></p></div>
  <div role='button' disabled class='col-10 google-preview bg-light rounded'><small>";
  $parse1 = parse_url($redirectedUrl);
  if (isset($parse['path'])) {
    $path = mb_strimwidth(
      $parse1['path'],
      1,
      strlen($parse1['path'])
    );
    echo $parse1['scheme'] . "://" . $parse1['host'] . "  >" . $path;
  } else echo $redirectedUrl;
  echo '</small><h3 class="google_preview_heading"> ';
  foreach ($title as $e)
  echo $e->innerhtml;
  echo '</h3><p class="text-muted w-75">';
  if (isset($meta_data['description']))
                foreach ($desc as $e)
                  echo mb_strimwidth($e, 0, 165, "...");

  echo "</p></div>
  </div>
  <div class='row mx-3 border-bottom'>
  <div class='col-2'><p><strong>Keywords Check:</strong></p></div>
  <div class='col-10'>";
  echo $keywords[0];
  echo
"</div>
 </div>
 <div class='row mx-3 border-bottom'>
 <div class='col-2'>
 <p><strong>Iframe Check:</strong></p>
 </div>
 <div class='col-10'>
 ";
 if (count($iframe) === 0) {
  echo "<p class ='text-success'>No Iframe Tag found <i class='ml-5 bi bi-check-circle-fill'></i></p>";
} else {
  echo "<p class ='text-danger'> Iframe Tag found<i class='ml-5 bi bi-check-x-fill'></i></p>";
}
 echo "</div>
 </div>
 <div class='row mx-3 border-bottom'>
 <div class='col-2'>
 <p><strong>H1 Check:</strong></p>
 </div>
 <div class='col-10'>
 ";
 if (!empty($domain)) {
  $h1 = $html->find('h1');
  $h1_check = count($h1);
  if ($h1_check == 0) {
    echo "<p class='text-danger'>NO H1 Tag Found <i class='ml-5 bi bi-x-circle-fill'></i></p> ";
  } elseif ($h1_check >= 1) {
    foreach ($h1 as $e) {
      echo "<p class='text-success'>".$e->innerhtml . "<i class='ml-5 bi bi-check-circle-fill'></i></p>";
    }
  }
}
 echo"
 </div>
 <div class='col-2'>
 <p><strong>H1 Count:</strong></p>
 </div>
 <div class='col-10'>";
 if ($h1_check == 1) {
  echo "<p class='text-success'>There is" . $h1_check . "  H1 Tag<i class='ml-5 bi bi-check-circle-fill'></i></p>";
} elseif ($h1_check == 0)
  echo "<p class='text-danger'>There is No H1 Tag<i class='ml-5 bi bi-check-x-fill'></i></p>";
else {
  echo "<p class='text-danger'>There are" . $h1_check . " H1 Tags<i class='ml-5 bi bi-x-cirlce-fill'></i></p>";
}
echo "<p>Recommended 1 H1 Tag</p>";
echo "</div>

<div class='col-2'>
<p><strong>H1 Length:</strong></p>
</div>
<div class='col-10'>";
foreach ($h1  as $e) {
  $h1length = strlen($e->innerhtml);
  if ($h1_check == 0) {
    echo "<p class='text-danger'>No H1 Tag Found <i class='ml-5 bi bi-x-cirlce-fill'></i></p>";
  } else {
    if ($h1length < 5) {
      echo "<p class='text-danger'>H1 Length is" . $h1length . " Characters <i class='ml-5 bi bi-x-cirlce-fill'></i></p>";
    } elseif ($h1length >= 5 && $h1length <= 70) {
      echo "<p class ='text-success'>H1 length is " . $h1length . " Characters <i class='ml-5 bi bi-check-cirlce-fill'></i></p>";
    } elseif ($h1length >= 70 && $h1length <= 85) {
      echo "<p class ='text-warning'>H1 length is " . $h1length . " Characters<i class='ml-5 bi bi-exclamation-cirlce-fill'></i></p>";
    } elseif ($h1length >= 85) {
      echo "<p class ='text-danger'>H1 length is " . $h1length . " Characters <i class='ml-5 bi bi-x-cirlce-fill'></i></p>";
    }
    echo "<span> Recommended 5 - 70 Characters</span>";
  }
}
echo"</div>
<div class='col-2'>
<p><strong>H1 = Title:</strong></p>
</div>
<div class='col-10'>"; 
foreach ($title as $e) {
  foreach ($h1 as $e1) {

    if ($e->innerhtml === $e1->innerhtml) {
      echo "<p class='text-danger'>H1 is equal to Title <i class='ml-5 bi bi-x-cirlce-fill'></i></p>";
    } elseif ($e->innerhtml !== $e1->innerhtml) {
      echo "<p class='text-success'>H1 is not equal to Title <i class='ml-5 bi bi-check-cirlce-fill'></i></p>";
    }
  }
}
echo"</div>
</div>
<div class='row mx-3 border-bottom'>
<h5>H1 - H6 Check</h5>";
echo '<div class="table-responsive">
<table class="table table-bordered">
  <tr>
    <td>H1</td>
    <td>H2</td>
    <td>H3</td>
    <td>H4</td>
    <td>H5</td>
    <td>H6</td>
  </tr>
';
$h2 = $html->find('h2');
$h3 = $html->find('h3');
$h4 = $html->find('h4');
$h5 = $html->find('h5');
$h6 = $html->find('h6');
echo "<tr>";
echo "<td>" . count($h1) . "</td>";
echo "<td>" . count($h2) . "</td>";
echo "<td>" . count($h3) . "</td>";
echo "<td>" . count($h4) . "</td>";
echo "<td>" . count($h5) . "</td>";
echo "<td>" . count($h6) . "</td>";
echo "</tr>";
echo '</table>
</div>
';
echo "<div class='row  border-bottom'><div class ='col-6 col-md-2'>H1</div>";
echo "<div class ='col-6 col-md-10'>";
if (count($h1) != 0) {
  foreach ($h1 as $e) {
    echo $e->plaintext . "<br>";
  }
}

echo "</div></div>";
echo "<div class='row  border-bottom'><div class ='col-6 col-md-2'>H2</div>";
echo "<div class ='col-6 col-md-10'>";
if (count($h2) != 0) {
  foreach ($h2 as $e) {
    echo $e->innerhtml . "<br>";
  }
}
echo "</div></div>
";
echo "<div class='row  border-bottom'><div class ='col-6 col-md-2'>H3</div>";
echo "<div class ='col-6 col-md-10'>";
if (count($h3) != 0) {
  foreach ($h3 as $e) {
    echo $e->innerhtml . "<br>";
  }
}
echo "</div></div>";
echo "<div class='row  border-bottom'><div class ='col-6 col-md-2'>H4</div>";
echo "<div class ='col-6 col-md-10'>";
if (count($h4) != 0) {
  foreach ($h4 as $e) {
    echo $e->innerhtml . "<br>";
  }
}
echo "</div></div>";
echo "<div class='row  border-bottom'><div class ='col-6 col-md-2'>H5</div>";
echo "<div class ='col-6 col-md-10'>";
if (count($h5) != 0) {
  foreach ($h5 as $e) {
    echo $e->innerhtml . "<br>";
  }
}
echo "</div></div>";
echo  "
<div class='row  '><div class ='col-6 col-md-2'>H6</div>";
          echo "<div class ='col-6 col-md-10'>";
          if (count($h6) != 0) {
            foreach ($h6 as $e) {
              echo $e->innerhtml . "<br>";
            }
          }
          echo "</div></div>
";
echo
"</div>";
echo '<div class ="row mx-3 border-bottom">
<div class ="col-2"><p><strong>Text Length:</strong></p></div>';
echo "<div class='col-10'><p>".$text_length . " Characters</p></div>";
echo '
</div>';
echo '<div class ="row mx-3 border-bottom">
<div class ="col-2"><p><strong>Text to Code Ratio:</strong></p></div>';
echo "<div class='col-10'><p>".round(($text_length / $code_length) * 100) . " %</p></div>";
echo '
</div>'; 
echo '<div class ="row mx-3 border-bottom">
<h5>Open Graph data :</h5>
<div class ="row  border-bottom">
<div class ="col-2"><p><strong>og:type:</strong></p></div>';
echo "<div class='col-10'><p>";
if (isset($og_data['og:type'])) {
  foreach ($og_data['og:type'] as $e)
    echo $e;
} else echo "<span class='text-danger'> Not Set</span>";

echo " </p></div></div>";
echo '<div class ="row  border-bottom">
<div class ="col-2"><p><strong>og:title</strong></p></div>';
echo "<div class='col-10'><p>"; 
if (isset($og_data['og:title'])) {
  foreach ($og_data['og:title'] as $e)
    echo $e;
} else echo "<span class='text-danger'> Not Set</span>"
;
echo " </p></div></div>";
echo '<div class ="row  border-bottom">
<div class ="col-2"><p><strong>og:app_id</strong></p></div>';
echo "<div class='col-10'><p>";
if (isset($og_data['fb:app_id'])) {
  foreach ($og_data['fb:app_id'] as $e)
    echo $e;
} else echo "<span class='text-danger'> Not Set</span>"; 
echo " </p></div></div>";
echo '<div class ="row  border-bottom">
<div class ="col-2"><p><strong>og:description</strong></p></div>';
echo "<div class='col-10'><p>"; 
if (isset($og_data['og:description'])) {
  foreach ($og_data['og:description'] as $e)
    echo $e;
} else echo "<span class='text-danger'> Not Set</span>"
;

echo  " </p></div></div>";
echo '<div class ="row  border-bottom">
<div class ="col-2"><p><strong>og:image</strong></p></div>';
echo "<div class='col-10'><p>"; 
if (isset($og_data['og:image'])) {
  foreach ($og_data['og:image'] as $e)
    echo $e;
} else echo "<span class='text-danger'> Not Set</span>"
;
echo" </p></div></div>";
echo '<div class ="row  border-bottom">
<div class ="col-2"><p><strong>og:url</strong></p></div>';
echo "<div class='col-10'><p>"; 
if (isset($og_data['og:url'])) {
  foreach ($og_data['og:url'] as $e)
    echo $e;
} else echo "<span class='text-danger'> Not Set</span>"
;
echo " </p></div></div>";
echo '
</div>';
$crawling = array();
$crawled = array();
$disallow = array();
//echo $start;
function getRobots($url)
{
  $robotsUrl = $url . "/robots.txt ";
  //echo $robotsUrl;

  ini_set("user_agent", "Agent (https://www.useragent.com)");
  $robots = @file_get_contents($robotsUrl);
  $robots = explode("\n", $robots);

  $robots = preg_grep('/[^\s]/', $robots);
  if (!empty($robots)) {
    echo "<span class='text-success'>Robots.txt found</span>";
    //print_r($robots);
  } else echo "<span class='text-danger'>file Not Found!</span>";
}
function getsitemap($url)
{
  $robotsUrl = $url . "/sitemap.xml ";
  //    echo $robotsUrl;

  ini_set("user_agent", "Agent (https://www.useragent.com)");
  $robots = @file_get_contents($robotsUrl);
  $robots = explode("\n", $robots);

  $robots = preg_grep('/[^\s]/', $robots);
  if (!empty($robots)) {
    echo "<span class='text-success'>Sitemap.xml found</span>";
    //print_r($robots);
  } else echo "<span class='text-danger'>file Not Found!</span>";
}

echo '<div class="row mx-3 border-bottom">
<div class="col-2"><p><strong>Robots.txt:</strong></p></div><div class="col-10">'; 
$result = getRobots($redirectedUrl);
echo'</div>
<div class="col-2"><p><strong>Sitemap.xml:</strong></p></div><div class="col-10">'; 
$result = getsitemap($redirectedUrl);
echo '</div>
</div>';
echo '<div class="row mx-3 border-bottom">
<div class="col-2"><p><strong>Clonical Link:</strong></p></div><div class="col-10">'; 
if (!empty($canonical)) {
  echo "<p class='text-success'>".$canonical[0]."</p>";
} else echo "<span class ='text-danger'>Canonical Link Not Found</span>";
echo '</div>';
echo '<div class="col-2"><p><strong>Status Code:</strong></p></div><div class="col-10">'; 
$Canonicalstatus = '';
if (!empty($canonical)) {

  $ch3 = curl_init($canonical[0]);
  curl_setopt($ch3, CURLOPT_HEADER, true);    // we want headers
  curl_setopt($ch3, CURLOPT_NOBODY, true);    // we don't need body
  //curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
  curl_setopt($ch3, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch3, CURLOPT_TIMEOUT, 10);
  $output = curl_exec($ch3);
  $info = curl_getinfo($ch3);
  //echo "Status Code is".."<br>";
  //echo  $info["size_download"];
  $Canonicalstatus = $info["http_code"];

  //echo '<pre>';
  //var_dump($info, $output);
  curl_close($ch3);
  if ($Canonicalstatus == 200)
    echo "<span class ='text-success'>" . $Canonicalstatus . "</span>";
} else
  echo "<span class ='text-danger'>" . $Canonicalstatus . "</span>";


echo '</div>';
echo '</div>';  
echo '<div class="row mx-3 border-bottom">
<div class="col-2"><p><strong>Underscore check:</strong></p></div>
<div class="col-10">';
if (strpos($domain, "_") == true) {
  echo "<p class='text-danger'>There is underscrore in the url please remove the underscore to make the url more user friendly</p>";
} elseif (strpos($domain, "_") == false) {
  echo "<p class='text-success' > The Url Does not contain Underscore</p>";
}
echo '</div>
</div>';
$globalRank = '';
      $countryRank = '';
      function alexaRank($url)
      {
        $alexaData = simplexml_load_file("https://data.alexa.com/data?cli=10&url=" . $url);
        $alexa['globalRank'] =  isset($alexaData->SD->POPULARITY) ? $alexaData->SD->POPULARITY->attributes()->TEXT : 0;
        $alexa['CountryRank'] =  isset($alexaData->SD->COUNTRY) ? $alexaData->SD->COUNTRY->attributes() : 0;
        return json_decode(json_encode($alexa), TRUE);
      }
      $alexa = alexaRank($redirectedUrl);
      $globalRank = "Global Alexa Rank of " . $parse['host'] . " is : " . $alexa['globalRank'][0];
      $countryRank = "Alexa Rank In " . $alexa['CountryRank']['@attributes']['NAME'] . " is : " . $alexa['CountryRank']['@attributes']['RANK'];
      echo '<div class="row mx-3 border-bottom">
      <div class="col-2"><p><strong>Country  Rank:</strong></p></div>
      <div class="col-10">';
      echo $countryRank;
      echo '</div>';
      echo '<div class="col-2"><p><strong>Global Rank:</strong></p></div>
      <div class="col-10">';
      
    echo $globalRank;
      echo '</div>
      </div>';
      echo '<div class="row mx-3 border-bottom">
      <div class="col-2"><p><strong>Domain age:</strong></p></div><div class="col-10">';
      if (strpos($redirectedUrl, ".pk") !== false) {
        echo ".pk whois server is not availible Go to pknic to get results";
      } else {
        $d = new DomainAge();
        echo $d->age($parse['host']);
      }

      echo '</div>
      </div>
      ';
      $whois = $trimmed_url;
      $ouput = shell_exec("whois $whois 2>&1");
    //  $url = explode("www.", $url);
      //print_r($url);
/*      if (count($url) == 1) {
        
        $ouput = shell_exec("whois $whois 2>&1");
      } elseif (count($url) == 2) {
        $whois = $url[1];
        $ouput = shell_exec("whois $whois 2>&1");
      }
  */       
      echo '<div class="row mx-3 border-bottom">
      <div class="col-2"><p><strong>Who is:</strong></p></div><div class="col-10">'; 
     echo '
     <div class="accordion accordion-flush bg-light" id="accordionExample">

       <div class="accordion-item">
         <h2 class="accordion-header bg-dark text-white" id="headingzero">
           <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapsezero" aria-expanded="false" aria-controls="collapsezero">
             WHO IS

         </h2>
         <div id="collapsezero" class="accordion-collapse collapse" aria-labelled="headingzero" data-bs-parent="#accordionExample">
           <div class="accordion-body">
             <pre>'.$ouput.'</pre>
           </div>
         </div>
       </div>
     </div>'; 
      echo'</div>
      </div>';
      echo '<div class="row mx-3 border-bottom">
<div class="col-2"><p><strong>Domain Authority:</strong></p></div>
<div class="col-10"><p>';
echo $domain_authority;
echo '</p></div></div>
<div class="row mx-3 border-bottom"><div class="col-2"><p><strong>Page Authority:</strong></p></div>
<div class="col-10"><p>';
echo $page_authority;
echo '</p></div></div>
<div class="row mx-3 border-bottom"><div class="col-2"><p><strong>Spam Score:</strong></p></div>
<div class="col-10"><p>';
echo $spam_score;
echo '</p></div>
</div>';

      echo '<div class="row mx-3 border-bottom">
      <div class="col-2"><p><strong>Schema Check:</strong></p></div>
      <div class="col-10"><pre>';
      echo $schema;
      echo '</pre></div>
      </div>';
      echo '<div class ="row mx-3 border-bottom">
<div class ="col-2"><p><strong>Favicon:</p></div>';
echo "<div class='col-10'>";
if (count($favicon) == 0) {
  echo "<p class ='text-danger'>Favicon not set <i class='ml-5 bi bi-x-cirlce-fill'></i></p>";
} elseif (count($favicon) != 0) {
  $src = $favicon[0];

  $pos_http = strpos($src, "http");
  $pos_slash = strpos($src, "/");
  if ($pos_http === 0) {
    echo "<img src='" . $src . "' height ='80' width ='100'>";
  } elseif ($pos_slash === 0) {

    $parse = parse_url($domain);
    $url = $parse['host']; // prints 'google.com'
    $ch5 = curl_init();
    // Grab URL and pass it to the variable.
    curl_setopt($ch5, CURLOPT_URL, $url);
    // Catch output (do NOT print!)
    curl_setopt($ch5, CURLOPT_RETURNTRANSFER, TRUE);
    // Return follow location true
    curl_setopt($ch5, CURLOPT_FOLLOWLOCATION, TRUE);
    $output = curl_exec($ch5);
    // Getinfo or redirected URL from effective URL
    $redirectedUrl = curl_getinfo($ch5, CURLINFO_EFFECTIVE_URL);
    curl_close($ch5);
    //echo $redirectedUrl;
    $src = $redirectedUrl . $src;
    echo "<img src='" . $src . "' height ='80' width ='100'>";
  } else {

    $parse = parse_url($domain);
    $url = $parse['host']; // prints 'google.com'
    $ch5 = curl_init();
    // Grab URL and pass it to the variable.
    curl_setopt($ch5, CURLOPT_URL, $url);
    // Catch output (do NOT print!)
    curl_setopt($ch5, CURLOPT_RETURNTRANSFER, TRUE);
    // Return follow location true
    curl_setopt($ch5, CURLOPT_FOLLOWLOCATION, TRUE);
    $output = curl_exec($ch5);
    // Getinfo or redirected URL from effective URL
    $redirectedUrl = curl_getinfo($ch5, CURLINFO_EFFECTIVE_URL);
    curl_close($ch5);

    $src = $redirectedUrl . "/" . $src;
    echo "<img src='" . $src . "' height ='80' width ='100'>";
  }
  //echo $src;
  //echo $pos;
}
echo " </div>";
echo '
</div>';
echo '<div class="row mx-3 border-bottom">
<caption class="caption-top p-3 ">';
$img = $html->find("img");
          echo    "Found " . count($img) . " images";
       echo "</caption>";
       echo '<div class="table-responsive">
       <table class="table table-bordered">
         <thead>
           <tr>
             <th scope="col">Preview</th>
             <th scope="col">Alt Attribute</th>
             <th scope="col">Title Attribute</th>
             <th scope="col">Size</th>
           </tr>

         </thead>
     ';
     foreach ($img as $e) {
      echo "<tr>";
      $src = $e->getAttribute('src');
      try {
        $alt = $e->getAttribute('alt');
      } catch (Exception $e) {

        $alt = "No alt Attribute";
      }
      try {
        $title = $e->getAttribute('title');
      } catch (Exception $e) {

        $title = "No Title Attribute";
      }
      //echo $e->outerhtml;
      //$src_img = $redirectedUrl.$src;
      //echo $src_img;
      $pos_http = strpos($src, "http");
      //echo $pos;
      $pos_slash = strpos($src, "/");

      //echo $src;
      //echo $pos_slash;
      if ($pos_http === 0) {
        $src_img = $src;
        //echo $src_img."<br>";

        echo "<td><img src='" . $src_img . "' width ='80' height ='50'></td>";
        echo "<td>" . $alt . "</td>";
        echo "<td>" . $title . "</td>";
        $ch2 = curl_init($src_img);
        curl_setopt($ch2, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch2, CURLOPT_TIMEOUT, 10);
        $output = curl_exec($ch2);
        $info = curl_getinfo($ch2);
        $imgsize = $info["size_download"];

        $imgsize = $imgsize / 1024;
        echo "<td>" . round($imgsize) . " KB</td>";
        curl_close($ch2);
      } elseif ($pos_slash === 0) {
        $url = $parse['host']; // prints 'google.com'
        $ch5 = curl_init();
        // Grab URL and pass it to the variable.
        curl_setopt($ch5, CURLOPT_URL, $url);
        // Catch output (do NOT print!)
        curl_setopt($ch5, CURLOPT_RETURNTRANSFER, TRUE);
        // Return follow location true
        curl_setopt($ch5, CURLOPT_FOLLOWLOCATION, TRUE);
        $output = curl_exec($ch5);
        // Getinfo or redirected URL from effective URL
        $redirectedUrl = curl_getinfo($ch5, CURLINFO_EFFECTIVE_URL);
        curl_close($ch5);

        $src_img = $redirectedUrl . $src;
        //echo $src_img."<br>";
        echo "<td><img src='" . $src_img . "' width ='80' height ='50'></td>";
        echo "<td>" . $alt . "</td>";
        echo "<td>" . $title . "</td>";
        $ch2 = curl_init($src_img);
        curl_setopt($ch2, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch2, CURLOPT_TIMEOUT, 10);
        $output = curl_exec($ch2);
        $info = curl_getinfo($ch2);
        $imgsize = $info["size_download"];

        $imgsize = $imgsize / 1024;
        echo "<td>" . round($imgsize) . " KB</td>";
        curl_close($ch2);
      } else {
        $url = $parse['host']; // prints 'google.com'
        $ch5 = curl_init();
        // Grab URL and pass it to the variable.
        curl_setopt($ch5, CURLOPT_URL, $url);
        // Catch output (do NOT print!)
        curl_setopt($ch5, CURLOPT_RETURNTRANSFER, TRUE);
        // Return follow location true
        curl_setopt($ch5, CURLOPT_FOLLOWLOCATION, TRUE);
        $output = curl_exec($ch5);
        // Getinfo or redirected URL from effective URL
        $redirectedUrl = curl_getinfo($ch5, CURLINFO_EFFECTIVE_URL);
        curl_close($ch5);

        $src_img = $redirectedUrl . "/" . $src;
        //echo $src_img."<br>";
        echo "<td><img src='" . $src_img . "' width ='80' height ='50'></td>";
        echo "<td>" . $alt . "</td>";
        echo "<td>" . $title . "</td>";
        $ch2 = curl_init($src_img);
        curl_setopt($ch2, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch2, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch2, CURLOPT_TIMEOUT, 10);
        $output = curl_exec($ch2);
        $info = curl_getinfo($ch2);
        $imgsize = $info["size_download"];

        $imgsize = $imgsize / 1024;
        echo "<td>" . round($imgsize) . " KB</td>";
        curl_close($ch2);
      }

      echo "</tr>";
    }   
echo '
</table>
</div>
 </div>';
 echo "<h3>Links:</h3>";
 echo '       <div class="accordion" id="accordionExample">
 <div class="accordion-item">
   <h2 class="accordion-header" id="headingOne">
     <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne" aria-expanded="true" aria-controls="collapseOne">
       Internal Links
     </button>
   </h2>
   <div id="collapseOne" class="accordion-collapse collapse " aria-labelledby="headingOne" data-bs-parent="#accordionExample">
     <div class="accordion-body">
     <div class="table-responsive">
     <table class="table table-bordered">
                        <tr><th>#</th><th>Anchor</th><th>html</th></tr>
                        <tr><td>
     ';
     for ($n = 0; $n < count($internal_href); $n++) {
      $i = $n + 1;
      //  echo $i =$n+1;
      echo "<tr><td>" . $i . "</td><td>" . $internal_href[$n] . "</td><td>" . $internal_html[$n] . "";
    }
    echo '</table>';
    echo '</div>
    </div>
           </div>
         </div>';
    echo '
    <div class="accordion-item">
    <h2 class="accordion-header" id="headingTwo">
      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTwo" aria-expanded="false" aria-controls="collapseTwo">
        External Links </button>
    </h2>
    <div id="collapseTwo" class="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#accordionExample">
      <div class="accordion-body">
         ';
         echo '<div class="table-responsive">';
         echo '<table class="table table-bordered">
   <tr><th>#</th><th>Anchor</th><th>html</th></tr>';
         echo '<tr><td>';
         for ($n = 0; $n < count($external_href); $n++) {
           $i = $n + 1;
           //  echo $i =$n+1;
           echo "<tr><td>" . $i . "</td><td>" . $external_href[$n] . "</td><td>" . $external_html[$n] . "";
         }
         echo '</table>';
         echo '</div>';
echo '</div>
</div>
</div>';
echo '<h3>Google Page Speed Index:</h3>';
echo '<div class="accordion" id="accordionExample">
<div class="accordion-item">
  <h2 class="accordion-header" id="headingthree">
    <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapsethree" aria-expanded="true" aria-controls="collapsethree">
      Desktop Page Speed Insight
    </button>
  </h2>
  <div id="collapsethree" class="accordion-collapse collapse " aria-labelledby="headingthree" data-bs-parent="#accordionExample">
    <div class="accordion-body">
      <div class="row">
        <div class="col-12 col-md-6">
          <p>
';
if ($response_desktop['page_score'] >= 90) {
  //var_dump($response_mobile);
  echo "DESKTOP PAGE SPEED INSIGHT SCORE :<span class='text-success'>" . $response_desktop['page_score'] . "</span>";
} elseif ($response_desktop['page_score'] >= 50 && $response_desktop['page_score'] < 90) {
  //var_dump($response_mobile);
  echo "DESKTOP PAGE SPEED INSIGHT SCORE :<span class='text-waning'>" . $response_desktop['page_score'] . "</span>";
} elseif ($response_desktop['page_score'] >= 0 && $response_desktop['page_score'] < 50) {
  //var_dump($response_mobile);
  echo "DESKTOP PAGE SPEED INSIGHT SCORE :<span class='text-danger'>" . $response_desktop['page_score'] . "</span>";
}
echo '            </p>

</div>
<div class="col-12 col-md-6 desktop-view">
<img src='.$response_desktop['screenshot'].' height="235" width="270" alt="">

</div>
<div class="col-12">
  <div class="row">
    <h5>Lab Data </h5>
    <div class="col-6">
      <p>
        First Contentful Paint <strong>
        ';
        if ($response_desktop['fcp_nv'] <= 1800) {
          echo "<span class = 'text-success'>" . $response_desktop['fcp'] . "</span>";
        } elseif ($response_desktop['fcp_nv'] > 1800  && $response_desktop['fcp_nv'] <= 3000) {

          echo "<span class = 'text-warning'>" . $response_desktop['fcp'] . "</span>";
        } elseif ($response_desktop['fcp_nv'] > 3000) {

          echo "<span class = 'text-danger'>" . $response_desktop['fcp'] . "</span>";
        }
        echo '                        </strong>
        </p>
      </div>
      <div class="col-6">
        <p>
          Time to Interactive <strong>
';
if ($response_desktop['ti_nv'] <= 3800) {
  echo "<span class = 'text-success'>" . $response_desktop['ti'] . "</span>";
} elseif ($response_desktop['ti_nv'] > 3800 && $response_desktop['ti_nv'] <= 7300) {
  echo "<span class = 'text-warning'>" . $response_desktop['ti'] . "</span>";
} elseif ($response_desktop['ti_nv'] > 7300) {

  echo "<span class='text-danger'>" . $response_desktop['ti'] . "</span>";
}
echo '                        </strong>
</p>
</div>
<div class="col-6">
<p>Speed Index
  <strong>
';
if ($response_desktop['si_nv'] <= 3400) {
  echo "<span class = 'text-success'>" . $response_desktop['si'] . "</span>";
} elseif ($response_desktop['si_nv'] > 3400  && $response_desktop['si_nv'] <= 5800) {

  echo "<span class = 'text-warning'>" . $response_desktop['si'] . "</span>";
} elseif ($response_desktop['si_nv'] > 5800) {

  echo "<span class = 'text-danger'>" . $response_desktop['si'] . "</span>";
}
echo ' </strong>
</p>
</div>
<div class="col-6">
<p>Total Blocking Time

  <strong>';
 
  if ($response_desktop['tbl_nv'] <= 200) {
    echo "<span class = 'text-success'>" . $response_desktop['tbl'] . "</span>";
  } elseif ($response_desktop['tbl_nv'] > 200  && $response_desktop['tbl_nv'] <= 600) {

    echo "<span class = 'text-warning'>" . $response_desktop['tbl'] . "</span>";
  } elseif ($response_desktop['tbl_nv'] > 600) {

    echo "<span class = 'text-danger'>" . $response_desktop['tbl'] . "</span>";
  }
  echo '</strong>
  </p>
</div>
<div class="col-6">
  <p>Largest Contentful Paint
    <strong>
    ';
    if ($response_desktop['lcp_nv'] <= 2500) {
      echo "<span class = 'text-success'>" . $response_desktop['lcp'] . "</span>";
    } elseif ($response_desktop['lcp_nv'] > 2500  && $response_desktop['lcp_nv'] <= 4000) {

      echo "<span class = 'text-warning'>" . $response_desktop['lcp'] . "</span>";
    } elseif ($response_desktop['lcp_nv'] > 4000) {

      echo "<span class = 'text-danger'>" . $response_desktop['lcp'] . "</span>";
    }
echo '                         </strong>
</p>
</div>
<div class="col-6">
<p>Cumulative Layout Shift
  <strong>
';
if ($response_desktop['cls'] <= 0.1) {
  echo "<span class = 'text-success'>" . $response_desktop['cls'] . "</span>";
} elseif ($response_desktop['cls'] > 0.1  && $response_desktop['cls'] <= 0.25) {

  echo "<span class = 'text-warning'>" . $response_desktop['cls'] . "</span>";
} elseif ($response_desktop['cls'] > 0.25) {

  echo "<span class = 'text-danger'>" . $response_desktop['cls'] . "</span>";
}

echo '                         </strong>
</p>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
<div class="accordion-item">
<h2 class="accordion-header" id="headingfour">
<button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapsefour" aria-expanded="false" aria-controls="collapsefour">
Mobile Page Speed Insight </button>
</h2>
<div id="collapsefour" class="accordion-collapse collapse" aria-labelledby="headingfour" data-bs-parent="#accordionExample">
<div class="accordion-body">
<div class="row">
<div class="col-12 col-md-6">
<p>
';
if ($response_mobile['page_score'] >= 90) {
  //var_dump($response_mobile);
  echo "DESKTOP PAGE SPEED INSIGHT SCORE :<span class='text-success'>" . $response_mobile['page_score'] . "</span>";
} elseif ($response_mobile['page_score'] >= 50 && $response_mobile['page_score'] < 90) {
  //var_dump($response_mobile);
  echo "DESKTOP PAGE SPEED INSIGHT SCORE :<span class='text-warning'>" . $response_mobile['page_score'] . "</span>";
} elseif ($response_mobile['page_score'] >= 0 && $response_mobile['page_score'] < 50) {
  //var_dump($response_mobile);
  echo "MOBILE PAGE SPEED INSIGHT SCORE :<span class='text-danger'>" . $response_mobile['page_score'] . "</span>";
}

echo '                   </p>
</div>
<div class="col-12 col-md-6 mobile-view">
<img src='.$response_mobile['screenshot'].' class="rounded" height="200" width="84" alt="">


</div>
<div class="col-12">
  <div class="row">
    <h5>Lab Data </h5>
    <div class="col-6">
      <p>
        First Contentful Paint <strong>';
        if ($response_mobile['fcp_nv'] <= 1800) {
          echo "<span class = 'text-success'>" . $response_mobile['fcp'] . "</span>";
        } elseif ($response_mobile['fcp_nv'] > 1800  && $response_mobile['fcp_nv'] <= 3000) {

          echo "<span class = 'text-warning'>" . $response_mobile['fcp'] . "</span>";
        } elseif ($response_mobile['fcp_nv'] > 3000) {

          echo "<span class = 'text-danger'>" . $response_mobile['fcp'] . "</span>";
        }
       
echo ' </strong>
</p>
</div>
<div class="col-6">
<p>
  Time to Interactive <strong>
 ';
 if ($response_mobile['ti_nv'] <= 3800) {
  echo "<span class = 'text-success'>" . $response_mobile['ti'] . "</span>";
} elseif ($response_mobile['ti_nv'] > 3800 && $response_mobile['ti_nv'] <= 7300) {
  echo "<span class = 'text-warning'>" . $response_mobile['ti'] . "</span>";
} elseif ($response_mobile['ti_nv'] > 7300) {

  echo "<span class='text-danger'>" . $response_mobile['ti'] . "</span>";
}

echo '
</strong>
</p>
</div>
<div class="col-6">
<p>Speed Index
  <strong>
 ';
 if ($response_mobile['si_nv'] <= 3400) {
  echo "<span class = 'text-success'>" . $response_mobile['si'] . "</span>";
} elseif ($response_mobile['si_nv'] > 3400  && $response_mobile['si_nv'] <= 5800) {

  echo "<span class = 'text-warning'>" . $response_mobile['si'] . "</span>";
} elseif ($response_mobile['si_nv'] > 5800) {

  echo "<span class = 'text-danger'>" . $response_mobile['si'] . "</span>";
}

echo ' </strong>
</p>
</div>
<div class="col-6">
<p>Total Blocking Time

  <strong>';

  if ($response_mobile['tbl_nv'] <= 200) {
    echo "<span class = 'text-success'>" . $response_mobile['tbl'] . "</span>";
  } elseif ($response_mobile['tbl_nv'] > 200  && $response_mobile['tbl_nv'] <= 600) {

    echo "<span class = 'text-warning'>" . $response_mobile['tbl'] . "</span>";
  } elseif ($response_mobile['tbl_nv'] > 600) {

    echo "<span class = 'text-danger'>" . $response_mobile['tbl'] . "</span>";
  }
  echo '
  </strong>
                       </p>
                     </div>
                     <div class="col-6">
                       <p>Largest Contentful Paint
                         <strong>
                         
  ';
  if ($response_mobile['lcp_nv'] <= 2500) {
    echo "<span class = 'text-success'>" . $response_mobile['lcp'] . "</span>";
  } elseif ($response_mobile['lcp_nv'] > 2500  && $response_mobile['lcp_nv'] <= 4000) {

    echo "<span class = 'text-warning'>" . $response_mobile['lcp'] . "</span>";
  } elseif ($response_mobile['lcp_nv'] > 4000) {

    echo "<span class = 'text-danger'>" . $response_mobile['lcp'] . "</span>";
  }

  echo ' </strong>
  </p>
</div>
<div class="col-6">
  <p>Cumulative Layout Shift
    <strong>
   ';
   if ($response_mobile['cls'] <= 0.1) {
    echo "<span class = 'text-success'>" . $response_mobile['cls'] . "</span>";
  } elseif ($response_mobile['cls'] > 0.1  && $response_mobile['cls'] <= 0.25) {

    echo "<span class = 'text-warning'>" . $response_mobile['cls'] . "</span>";
  } elseif ($response_mobile['cls'] > 0.25) {

    echo "<span class = 'text-danger'>" . $response_mobile['cls'] . "</span>";
  }
  echo '</strong>
  </p>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
  ';
echo  "</div>";

echo '<a class="btn btn-primary my-5" href="javascript:getPDF()">Generate Pdf</a>'; 
}
elseif(isset($_POST['domain']) && !empty($error)){
  echo "<div class='alert alert-danger my-3' role='alert'>".$error."<button type='button' class='btn-close offset-9' data-bs-dismiss='alert' aria-label='Close'></button></div>";
}