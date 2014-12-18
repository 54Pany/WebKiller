<?php
/**************webKiller*****************
[+] Author: 白云下的p4ny
[+] 版本: v2.0
[+]License: GPL-2
请自行判断、审核、对比原文件。           
*/
define('PASSWORD', '123123');
error_reporting(E_ERROR);
ini_set('max_execution_time',20000);
ini_set('memory_limit','512M');
header("content-Type: text/html; charset=utf-8");
if($_GET[action]=='delself'){
$url = $_SERVER['PHP_SELF'];
$file= substr( $url , strrpos($url , '/')+1 );
if (file_exists("./".$file)){
      @unlink ("./".$file);
}
}
if(!isset($_COOKIE['webKillerpwd']) || $_COOKIE['webKillerpwd'] != md5(PASSWORD)) {
    if($_SERVER['REQUEST_METHOD']=='GET'){
echo '<html>
<head><title>安全认证</title>
</head>
<style>
table{font-size:9pt;}
</style>
<body><br>
<form method="post" action="">
<table border="0" cellpadding="3" cellspacing="1" align="center" width="300" bgcolor="#3399CC">
<tr height="25" bgcolor="#E7E7E7"><td colspan="2"><b>WebKiller--</b>验证</td></tr>
<tr height="25" bgcolor="#e7f7f7" ><td align="right">Password：</td><td><input type="text" name="pwd"></td></tr>';
echo '<tr height="25" bgcolor="#e7f7f7" ><td></td><td><input type="submit" name="login_submit" value="进入">';
echo "<font color=red>".$str."</font>";
echo '</td></tr>
</table>
</form>
</body>
</html>';
die();
}
else {
        if (isset($_POST['pwd']) && $_POST['pwd'] == PASSWORD){
			$mypwd = md5(PASSWORD);
            setcookie('webKillerpwd', $mypwd);
			echo "<script>document.cookie='webKillerpwd=".$mypwd."';window.location.href='';</script>";
			die();
        } else {
            $str="密码错误!";
echo '<html>
<head><title>安全认证</title>
</head>
<style>
table{font-size:9pt;}
</style>
<body><br>
<form method="post" action="">
<table border="0" cellpadding="3" cellspacing="1" align="center" width="300" bgcolor="#3399CC">
<tr height="25" bgcolor="#E7E7E7"><td colspan="2"><b>WebKiller--</b>验证</td></tr>
<tr height="25" bgcolor="#e7f7f7" ><td align="right">Password：</td><td><input type="text" name="pwd"></td></tr>';
echo '<tr height="25" bgcolor="#e7f7f7" ><td></td><td><input type="submit" name="login_submit" value="进入">';
echo " <font color=red>".$str."</font>";
echo '</td></tr>
</table>
</form>
</body>
</html>';
            die();
        }
    }
}
$shellLib = array(
    '/function\_exists\s*\(\s*[\'|\"](popen|exec|proc\_open|system|passthru)+[\'|\"]\s*\)/i',
    '/(exec|shell\_exec|system|passthru)+\s*\(\s*\$\_(\w+)\[(.*)\]\s*\)/i',
    '/((udp|tcp)\:\/\/(.*)\;)+/i',
    '/preg\_replace\s*\((.*)\/e(.*)\,\s*\$\_(.*)\,(.*)\)/i',
    '/preg\_replace\s*\((.*)\(base64\_decode\(\$/i',
    '/(eval|assert|include|require|include\_once|require\_once)+\s*\(\s*(base64\_decode|str\_rot13|gz(\w+)|file\_(\w+)\_contents|(.*)php\:\/\/input)+/i',
    '/(eval|assert|include|require|include\_once|require\_once|array\_map|array\_walk)+\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)+\[(.*)\]\s*\)/i',
    '/eval\s*\(\s*\(\s*\$\$(\w+)/i',
    //特征库.
);
function shellScan($fileexs,$dir,$shellLib){
	if(($handle = @opendir($dir)) == false) 
	    return false;
	while ( false !== ( $filename = readdir ( $handle ))) {
		if($filename == '.' || $filename == '..') continue;
		$filepath = $dir.$filename;
		if(is_dir($filepath)){
			if(is_readable($filepath)) 
				shellScan($fileexs,$filepath.'/',$shellLib);
		}
			elseif(strpos($filename,';') > -1 || strpos($filename,'%00') > -1 || strpos($filename,'/') > -1) {
            			echo '<tr class="danger">
						<td>
							解析漏洞
						</td>
						<td>
						'.$filepath.'
						</td>
						</tr>';
						flush();
						ob_flush();
		}
		else{
			if(!preg_match($fileexs,$filename)) continue;
            if(filesize($filepath) > 10000000) continue;
            $fp = fopen($filepath,'r');
            $code = fread($fp,filesize($filepath));
            fclose($fp);
            if(empty($code)) continue;
            foreach($shellLib as $matche) {
                $array = array();
                preg_match($matche,$code,$array);
                if(!$array) continue;
                if(strpos($array[0],"\x24\x74\x68\x69\x73\x2d\x3e")) continue;
                $len = strlen($array[0]);
                if($len >= 5 && $len < 200) {
					echo '
					<tr class="danger">
						<td>
							'.htmlspecialchars($array[0]).'
						</td>
						<td>
							'.$filepath.'
						</td>
					</tr>';
                    //echo '特征 <input type="text" style="width:218px;" value="'.htmlspecialchars($array[0]).'"> '.$filepath.'<div></div>';
                    flush(); ob_flush(); break;
                }
            }
            unset($code,$array);
		}
	  }
	closedir($handle);
    return true;
}
function setdir($str) {
	$order=array('\\','//','//');
	$replace=array('/','/','/');
	return str_replace($order,$replace,rtrim($str)); 
}
?>
<!DOCTYPE html>
<html>
<head>
<title>webKiller V 2.0</title>
<style>
body{font-family:"Helvetica Neue",Helvetica,Microsoft Yahei,Arial,sans-serif;background-color:#f8f8f8;color:#333}a{color:#09c;text-decoration:none}a:hover{color:#08a;text-decoration:underline}input{border:1px solid #ccc;border-radius:3px 3px 3px 3px;-webkit-border-radius:3px;-moz-border-radius:3px;color:#555;display:inline-block;line-height:normal;padding:4px;width:350px}.hero-unit{margin:0 auto 0 auto;font-size:18px;font-weight:200;line-height:30px;border-radius:6px;padding:20px 60px 10px}.hero-unit>h2{text-shadow:2px 2px 2px #ccc;font-weight:normal}.btn{display:inline-block;padding:6px 12px;margin-bottom:0;font-size:14px;font-weight:500;line-height:1.428571429;text-align:center;white-space:nowrap;vertical-align:middle;cursor:pointer;border:1px solid transparent;border-radius:4px;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;-o-user-select:none;user-select:none}.btn:focus{outline:thin dotted #333;outline:5px auto -webkit-focus-ring-color;outline-offset:-2px}.btn:hover,.btn:focus{color:#fff;text-decoration:none}.btn:active,.btn.active{outline:0;-webkit-box-shadow:inset 0 3px 5px rgba(0,0,0,0.125);box-shadow:inset 0 3px 5px rgba(0,0,0,0.125)}.btn-default{color:#fff;background-color:#474949;border-color:#474949}.btn-default:hover,.btn-default:focus,.btn-default:active,.btn-default.active{background-color:#3a3c3c;border-color:#2e2f2f}.btn-success{color:#333;background-color:#fff;border-color:#ccc}.btn-success:hover,.btn-success:focus,.btn-success:active,.btn-success.active{background-color:#4cae4c;border-color:#449d44}.btn-primary{color:#fff;background-color:#428bca;border-color:#428bca}.btn-primary:hover,.btn-primary:focus,.btn-primary:active,.btn-primary.active{background-color:#357ebd;border-color:#3071a9}.main{width:960px;margin:0 auto}.title,.check{text-align:center}.check button{width:200px;font-size:20px}.check a.btn{color:#fff;text-decoration:none}.content{margin-top:20px;padding:15px 30px 30px;box-shadow:0 1px 1px #aaa;background:#fff}dt{font-size:25px}table{width:100%;border-collapse:collapse;border-spacing:0}th,td{text-align:left}td{border-bottom:solid 1px #e0e0e0;height:40px;vertical-align:top;line-height:40px}.item_t td{border-bottom:0}.item_y{word-wrap:break-word;word-break:break-word;width:860px;color:Red;text-indent:1em;padding-bottom:10px}.yt,.yv{line-height:1.7em}.yt{color:#f00}.yv{color:#00f}.item_n{width:860px;color:#0a0;text-indent:1em}.ads>ul{list-style:none;padding:0}.ads>ul>li{float:left;padding-right:20px}.foot{text-align:center;font-size:13px}.clearfix:before,.clearfix:after{display:table;content:" "}.clearfix:after{clear:both}.table .table{background-color:#fff}.table-condensed>thead>tr>th,.table-condensed>tbody>tr>th,.table-condensed>tfoot>tr>th,.table-condensed>thead>tr>td,.table-condensed>tbody>tr>td,.table-condensed>tfoot>tr>td{padding:5px}.table-striped>tbody>tr:nth-child(odd)>td,.table-striped>tbody>tr:nth-child(odd)>th{background-color:#f9f9f9}.table>thead>tr>td.danger,.table>tbody>tr>td.danger,.table>tfoot>tr>td.danger,.table>thead>tr>th.danger,.table>tbody>tr>th.danger,.table>tfoot>tr>th.danger,.table>thead>tr.danger>td,.table>tbody>tr.danger>td,.table>tfoot>tr.danger>td,.table>thead>tr.danger>th,.table>tbody>tr.danger>th,.table>tfoot>tr.danger>th{background-color:#f2dede}.table-hover>tbody>tr>td.danger:hover,.table-hover>tbody>tr>th.danger:hover,.table-hover>tbody>tr.danger:hover>td,.table-hover>tbody>tr.danger:hover>th{background-color:#ebcccc}
</style>
<script src="http://www.knownsec.com/static/js/jquery-1.6.4.min.js"></script>
</head>
<body>
<div class="main">
    <div class="hero-unit">
        <h2 class="title">webKiller V 2.0</h2>
        <div class="check">
            <a id='logout' class="btn btn-primary" onclick="this.innerText='正在注销..';logout()">Logout</a>
            <a id='del' class="btn btn-primary" value="delself" onclick="this.innerText='正在销毁..';getLabelsGet()">Delself</a>
        </div>
    </div>
    <div class="content">
        <table>
            <thead>
            <tr> 
                <div id='scanmod'>
                    <form  id="scan" method="post" action="">
                        检测路径：
                        <input type="text" id="chk_dir" name="dir" value="<?php echo($_POST['dir'] ? setdir($_POST['dir'].'/') : setdir($_SERVER['DOCUMENT_ROOT'].'/'));?>"/> 不填写为本文件所在的目录
                        <br />
                        文件后缀：
                        <input type="text" id="file_types" name="fileexs" value=".php|.inc|.phtml"/> 文件类型，如：php,inc
                        <br /><br/>
                        <input class="btn btn-success" style="width:100px;" type="submit" value="Scan" onclick="this.value='扫描中...'"/>
                    </form><button class="btn btn-success" style="width:100px;" onclick="clera();">Reset</button>
                </div>
			</tr>
			</thead><br/>
		</table>
		<?php
			echo '<table id="result" class="table table-striped table-condensed" >
			<thead id="theadtitle" style="display:none">
				<tr>
					<th>
						特征
					</th>
					<th>
						路径
					</th>
				</tr>
			</thead>
			<tbody>';
			if(file_exists($_POST['dir']) && $_POST['fileexs']) {
			$dir = setdir($_POST['dir'].'/');
			$fileexs = '/('.str_replace('.','\\.',$_POST['fileexs']).')/i';
			echo '<script>document.getElementById("theadtitle").style.display="";</script>';
			$result = shellScan($fileexs,$dir,$shellLib) ? '<div></div>扫描完毕' : '<div></div>扫描中断';
			echo '</tbody>
			</table>';
			}
		?>
	</div>
<script>
    function logout(){
        document.cookie='webKillerpwd=0';
        document.cookie='flag=0';
        location.reload();
    }
    function clera(){
        document.getElementById("file_types").value=".php|.inc|.phtml"; 
        document.getElementById("chk_dir").value="<?php echo($_POST['dir'] ? setdir($_POST['dir'].'/') : setdir($_SERVER['DOCUMENT_ROOT'].'/'));?>";
    }
	</script>
<script type="text/javascript">
	var xmlHttp;
	function GetXmlHttpObject(){
		if (window.XMLHttpRequest){
		  xmlhttp=new XMLHttpRequest();
		}else{
		  xmlhttp=new ActiveXObject("Microsoft.XMLHTTP");
		}
		return xmlhttp;
	}
	
	function getLabelsGet(){
		xmlHttp=GetXmlHttpObject();
		if (xmlHttp==null){
			alert('您的浏览器不支持AJAX！');
			return;
		}
		var id = 'delself';
		if( confirm('Delself ?') ){
		var url="<?php echo $_SERVER['PHP_SELF'];?>?action="+id;
		xmlHttp.open("GET",url);
		xmlHttp.onreadystatechange=getOkGet;
		xmlHttp.send();
		location.reload();
		}
	}
					   
	function getOkGet(){
		if(xmlHttp.readyState==1||xmlHttp.readyState==2||xmlHttp.readyState==3){                
		}
		if (xmlHttp.readyState==4 && xmlHttp.status==200){
			var d= xmlHttp.responseText;
		}
	}
</script>
</html>