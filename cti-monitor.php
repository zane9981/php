<?php
//Ubuntu
//apt-get install libssh2-php
//apt-get install php5-curl
//apt-get install mailutils

//CentOS
//yum install php-pecl-ssh2
//yum install php-redis
//yum install php-process
//yum install mailx

define ('EMAIL_ENABLE', true);
define ('EMAIL_CC','zenith@maxxday.com');
define ('EMAIL_TO','freedom@maxxday.com,abin@maxxday.com,hugo@maxxday.com');

define ('BROADCAST_PORT', 60000);
define ('BROADCAST_RECV_TIMEOUT', 2);
define ('BROADCAST_SERVER_TIMEOUT', 30);
define ('BROADCAST_MAIN_TIMEOUT', 2);
define ('MONITOR_FLAG','m~A!x@X#D%a^y&M*o(N)i-T+o:r;');

define ('REDIS_SERVER', 'cti-redis'); 
define ('REDIS_PORT', 6379);

define ('CHECK_DIE_COUNT', 3);
define ('CHECK_DISCONNECT_COUNT', 3);

define ('SERVER_TIMEOUT', 30);

define ('AST_USER', 'dreamstart');
define ('AST_PASS', 'google');


//define ('SSH_USER', 'freedom');
define ('SSH_USER', 'root');
define ('SSH_PASS', '123456');

define ('LOG_PATH', '/var/log/cti_monitor.log');

$check_servers = array(
    'asterisk',
    'webrtc',
    'opensips',
    'ivr',
    'webservice',
    'control',
);
$pids = array();

$local_ip = trim(`ifconfig | sed -n '2p' | awk -F ':' '{print $2}' | awk '{print $1}'`);
$broadcast_ip = trim(`ifconfig | sed -n '2p' | awk -F ':' '{print $3}' | awk '{print $1}'`);

if(!preg_match("/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/",$local_ip)) {
    outlog(__LINE__,$local_ip."\n");
    outlog(__LINE__,"Can not get local_ip.\n");
    exit(-1);
}

if(!preg_match("/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/",$broadcast_ip)) {
    outlog(__LINE__,$broadcast_ip."\n");
    outlog(__LINE__,"Can not get broadcast_ip.\n");
    exit(-1);
}

date_default_timezone_set('PRC');

function format_cur_time()
{
    return date('Y-m-d H:i:s',time());
}

function outlog($line, $str)
{
    $newstr = '('.format_cur_time().'['.$line.']) '. $str;
    echo $newstr;
    file_put_contents (LOG_PATH, $newstr, FILE_APPEND | LOCK_EX);
}

/*
function sendmail($str)
{
    $cmd = <<<EOF
    sendmail -t
<<EOF2
From:
it_info@maxxday.com
To:
hugo@maxxday.com
Cc:
zenith@maxxday.com,arook@maxxday.com,xkp@maxxday.com,mark@maxxday.com,blue@maxxday.com
Subject:CTI Monitor warning
-------------------------------------------------------------------
$str
-------------------------------------------------------------------
EOF2
EOF;
    exec($cmd);
}  
*/

function sendmail($str)
{
    if(!EMAIL_ENABLE) return;

    $cc = EMAIL_CC;
    $mailto = EMAIL_TO;

    $str = '['.format_cur_time().'] '.$str;

    $cmd = <<<EOF
echo "$str" | mailx -r "it_info@maxxday.com" -s "CTI Monitor warning" -S smtp="smtp.exmail.qq.com" -S smtp-auth-user="it_info@maxxday.com" -S smtp-auth-password="password" -c "$cc" $mailto
EOF;

    exec($cmd);
}


function send_origenate_to_ast($local_ip, $ast_ip, $user, $pass, $timeout_second)
{
    $socket = @fsockopen($ast_ip,5038, $errno, $errstr, $timeout_second);
    if (!$socket) {
        outlog(__LINE__,"Socket Open $ast_ip:5038(asterisk) failed(errno=$errno,errstr=$errstr)\n");
        return false;
    }
    fputs($socket, "Action: Login\r\n");
    fputs($socket, "UserName: $user\r\n");
    fputs($socket, "Secret: $pass\r\n\r\n");
    usleep(100000);
    fputs($socket, "Action: Originate\r\n");
    fputs($socket, "Async: true\r\n");
    fputs($socket, "ActionID: 999999999\r\n");
    fputs($socket, "Channel: sip/12345678@$local_ip\r\n");
    fputs($socket, "Application: NoOp\r\n");
    fputs($socket, "Data: monitor\r\n\r\n");
    //sleep(1);
    //echo fread($socket,1024);
    usleep(100000);
    fclose($socket);

    return true;
}

function listen_sip($local_ip)
{
    $server = "udp://$local_ip:5060";
    $socket = @stream_socket_server($server, $errno, $errstr, STREAM_SERVER_BIND);
    if (!$socket) {
        outlog(__LINE__,"Create SIP($server) Server failed(errno=$errno,errstr=$errstr)\n");
        return false;
    }

    return $socket;
}

function read_sip($socket, $timeout_second)
{
    $ret = false;
    stream_set_blocking($socket,0);

    $readfds[] = $socket;
    if (stream_select( $readfds, $writefds = null, $e = null, $t = $timeout_second)) {
        foreach ($readfds as $key => $rfd) {
            $buf = fread($socket, 64);
            //var_dump($buf);
            if (strncmp($buf,'INVITE sip:1234',strlen('INVITE sip:1234')) == 0) {
                $ret = true;
            }
        }
    }
    fclose($socket);
    return $ret;
}


function start_remote_server($ip, $user, $pass, $server_flag)
{
    $ret = false;
    $connection = @ssh2_connect($ip,22);

    if (!$connection) {
        outlog(__LINE__,"ssh2_connect(ip=$ip) field\n");
        return false;
    }

    if(!@ssh2_auth_password($connection, $user, $pass)) {
        outlog(__LINE__,"ssh2_auth_password (ip=$ip, user=$user, password=$pass) field\n");
        return false;
    }

    $cmd = "/etc/init.d/cti.start $server_flag";
    /*if(!($stream = @ssh2_exec($connection, "echo \"$pass\" | sudo -S ".$cmd))) {
        outlog(__LINE__,"ssh2_exec (ip=$ip,cmd=$cmd) field\n");
        return false;
    }

    outlog(__LINE__,"(ip=$ip) exec(cmd=$cmd)\n");
    stream_set_blocking($stream, true);
    $starttime = time();
    while($line = fgets($stream)) {
        flush();
        outlog(__LINE__,$line);
        if(time()-$starttime > 300) {
            break;
        }
    }
    fclose($stream);*/

    if (!($stream = ssh2_shell($connection,"xterm"))) {
        outlog(__LINE__,"ssh2_shell field\n");
        return false;
    }
    stream_set_blocking($stream, 0);
    sleep(2);
    fwrite($stream, "(echo \"$pass\" | sudo -S ".$cmd." &)\n");
    $starttime = time();
    for (;;) {
        $buf = fread($stream, 1024);
        if(strstr($buf,'cti.start_successful_flag')) {
            $ret = true;
            break;
        }
        if(time()-$starttime > 30) {
            break;
        }
    }
    fclose($stream);
    outlog(__LINE__,"Execte $cmd finish(ret=$ret)\n");

    return $ret;
}


function remove_server($name, $server_flag)
{
    $redis_name = $server_flag.'_servers';
    $redis = new redis();
    $redis->connect(REDIS_SERVER, REDIS_PORT);
    $redis->zrem($redis_name, $name);
    $redis->del($name);
    $redis->close();

    outlog(__LINE__,"Delete redis info ($redis_name, $name)\n");
}


function test_asterisk($remote_ip, $timeout_second)
{
    global $local_ip;
    $socket = listen_sip($local_ip);
    if ($socket) {
        if(send_origenate_to_ast($local_ip, $remote_ip, AST_USER, AST_PASS, $timeout_second)) {
            return read_sip($socket, $timeout_second);
        } else {
            fclose($socket);
        }
    }

    return false;
}


function test_opensips($remote_ip, $timeout_second)
{
    $ret = false;
    $fp = @stream_socket_client("udp://$remote_ip:5060", $errno, $errstr, 5);
    if ($fp) {
        $local_addr = stream_socket_get_name($fp,false);
        $option = <<<EOF
OPTIONS sip:anonymous@$remote_ip SIP/2.0\r
Via: SIP/2.0/UDP $local_addr;branch=z9hG4bKhjhs8ass877\r
Max-Forwards: 70\r
To: <sip:anonymous@$remote_ip>\r
From: "Anonymous" <sip:anonymous@anonymous.invalid>;tag=1928301774\r
Call-ID: a84b4c76e66710\r
CSeq: 63104 OPTIONS\r
Contact: <sip:anonymous@$local_addr>\r
Accept: application/sdp\r
Content-Length: 0\r\n
EOF;
        fwrite($fp, $option);

        stream_set_blocking($fp,0);
        $readfds[] = $fp;
        if (stream_select($readfds, $writefds = null, $e = null, $t = $timeout_second)) {
            foreach ($readfds as $key => $rfd) {
                $buf = fread($fp,128);
                //var_dump($buf);
                if(strncmp($buf, "SIP/2.0", strlen("SIP/2.0")) == 0) {
                    $ret = true;
                }
            }
        }
        fclose($fp);
    } else {
        outlog(__LINE__,"Can not connect (udp://$remote_ip:5060),(errno=$errno),(errstr=$errstr)\n");
    }

    return $ret;
}


function test_webrtc($remote_ip, $timeout_second)
{
    $ret = false;
    $key = base64_encode(uniqid());
    $header = "GET / HTTP/1.1\r\n"
    ."pragma: no-cache\r\n"
    ."cache-control: no-cache\r\n"
    ."Upgrade: WebSocket\r\n"
    ."Connection: Upgrade\r\n"
    ."Sec-WebSocket-Key: $key\r\n"
    ."Sec-WebSocket-Version: 13\r\n"
    ."\r\n";

    $socket = @fsockopen($remote_ip,8080, $errno, $errstr, $timeout_second);
    if (!$socket) {
        outlog(__LINE__,"Socket Open $remote_ip:8080(webrtc) (errno=$errno),(errstr=$errstr) failed\n");
        return false;
    }

    if ($socket) {
        fwrite($socket, $header);

        stream_set_blocking($socket,0);
        $readfds[] = $socket;
        if (stream_select($readfds, $writefds = null, $e = null, $t = $timeout_second)) {
            foreach ($readfds as $key => $rfd) {
                $buf = fread($socket,64);
                if(strncmp($buf,'HTTP',strlen('HTTP')) == 0) {
                    $ret = true;
                }
                //var_dump($buf);
            }
        }
        fclose($socket);
    }

    return $ret;
}


function test_ivr($remote_ip, $timeout_second)
{
    $ret = false;
    $socket = @fsockopen($remote_ip, 4573, $errno, $errstr, $timeout_second);
    if (!$socket) {
        outlog(__LINE__,"Socket Open $remote_ip:4573(ivr) failed(errno=$errno,errstr=$errstr)\n");
        return false;
    }

    $__time = time();

    $send = <<<EOF
agi_network: yes
agi_network_script: ivrid=075522658052&callid=${__time}abc&groupid=100200
agi_request: agi://new-ivr02/ivrid=075522658052&callid=${__time}abc&groupid=100200
agi_channel: SIP/1001-0000004c
agi_language: en
agi_type: SIP
agi_uniqueid: 1456985395.152
agi_version: 13.6.0
agi_callerid: 075522733003
agi_calleridname: Rongbin Shen
agi_callingpres: 0
agi_callingani2: 0
agi_callington: 0
agi_callingtns: 0
agi_dnid: 075522658052
agi_rdnis: unknown
agi_context: voiceglue
agi_extension: 075522658052
agi_priority: 2
agi_enhanced: 0.0
agi_accountcode:
agi_threadid: 14044287594265\n\n
EOF;


    fwrite($socket,$send);

    stream_set_blocking($socket,0);
    $readfds[] = $socket;
    if (stream_select($readfds, $writefds = null, $e = null, $t = $timeout_second)) {
        foreach ($readfds as $key => $rfd) {
            $buf = fread($socket,256);

            if(strstr($buf,'welcome')) {
                $ret = true;
            }
            //var_dump($buf);
        }
    }

    fclose($socket);

    return $ret;
}


function test_webservice($ip, $timeout_second)
{
/*
    $url = "http://$ip/api/v1/callback/exten_event/get";

    $post_string = array (
        'appid' => 'ctitest',
        'uuid' => '686388A5-CFDA-4A2B-BEA8-236D2449BA29',
        'time' => '20160401141604',
        'sign' => '8455bb0d3077876b927fd5b41b2e12d7'
    );
 
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    //curl_setopt($ch, CURLOPT_POSTFIELDS, $post_string);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post_string));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout_second);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout_second);
    $result = curl_exec($ch);
    curl_close($ch);
    print_r($result);
*/



    $url = "http://$ip/api/v1/ping";

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout_second);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout_second);
    $result = curl_exec($ch);
    curl_close($ch);

    if (strcmp("{\"pong\":\"pong\"}\n",$result) == 0) {
        return true;
    }
    return false;
}


function test_control($remote_ip, $timeout_second)
{
    $ret = false;
    $fp = @stream_socket_client("udp://$remote_ip:8078", $errno, $errstr, 5);
    if ($fp) {
        $local_addr = stream_socket_get_name($fp,false);
        $wdata = "ping";
        fwrite($fp, $wdata);

        stream_set_blocking($fp,0);
        $readfds[] = $fp;
        if (stream_select($readfds, $writefds = null, $e = null, $t = $timeout_second)) {
            foreach ($readfds as $key => $rfd) {
                $buf = fread($fp,128);
                //var_dump($buf);
                if(strncmp($buf, "ping", strlen("ping")) == 0) {
                    $ret = true;
                }
            }
        }
        fclose($fp);
    } else {
        outlog(__LINE__,"Can not connect (udp://$remote_ip:8078),(errno=$errno),(errstr=$errstr)\n");
    }

    return $ret;
}

/*
function test_control($remote_ip, $timeout_second)
{
    $ret = false;
    $socket = @fsockopen($remote_ip, 8068, $errno, $errstr, $timeout_second);
    if (!$socket) {
        outlog(__LINE__,"Socket Open $remote_ip:8068(control) failed(errno=$errno,errstr=$errstr)\n");
        return false;
    }

    $uVersion = 1;
    $uId = 1234;
    $uMainFuncType = 1;
    $uDataType = 1;
    $uDataLen = 0;
    $usReserve = 0;
    $send = pack('LLLLLS', $uVersion, $uId, $uMainFuncType, $uDataType, $uDataLen, $usReserve);

    fwrite($socket,$send);

    stream_set_blocking($socket,0);
    $readfds[] = $socket;
    if (stream_select($readfds, $writefds = null, $e = null, $t = $timeout_second)) {
        foreach ($readfds as $key => $rfd) {
            $buf = fread($socket,256);
            if ($buf == $send) {
                $ret = true;
            }
        }
    }

    fclose($socket);

    return $ret;
} 
*/ 

/*
function check_server($server_flag, $servers)
{
    $test_func = "test_$server_flag";

    foreach ($servers as $key => $ser) {
        if ($servers[$key]['die'] < CHECK_DIE_COUNT) { 
            if ($test_func($ser['ip'],5)) {
                $servers[$key]['die'] = 0;
            } else {
                ++$servers[$key]['die'];
                if ($servers[$key]['die'] >= CHECK_DIE_COUNT) {
                    //Send email.
                    outlog(__LINE__,"$server_flag [ name=$key,ip=$ser[ip] ] die\n");
                }
            }
        } else {
            if(start_remote_server($ser['ip'], SSH_USER, SSH_PASS, $server_flag)) {
                $servers[$key]['disconnect'] = 0;
                $servers[$key]['die'] = 0;
            } else {
                ++$servers[$key]['disconnect'];
                if ($servers[$key]['disconnect'] >= CHECK_DISCONNECT_COUNT) {
                    //Send email.
                    outlog(__LINE__,"$server_flag [ name=$key,ip=$ser[ip] ] disconnect\n");
                    remove_server($key, $server_flag);
                    unset($servers[$key]);
                }
            }
        }
    }

    return $servers;
}
*/


function check_server($server_flag, &$servers, &$restart_servers)
{
    $test_func = "test_$server_flag";

    foreach ($servers as $key => $ser) {

        if ($test_func($ser['ip'],5)) {
            $servers[$key]['die'] = 0;
        } else {
            ++$servers[$key]['die'];
            if ($servers[$key]['die'] >= CHECK_DIE_COUNT) {
                $restart_servers[$key]['ip'] = $ser['ip'];
                $restart_servers[$key]['disconnect'] = 0;

                //Send email.
                outlog(__LINE__,"$server_flag [ name=$key,ip=$ser[ip] ] die\n");
                remove_server($key, $server_flag);
                unset($servers[$key]);
                sendmail("$server_flag [ name=$key,ip=$ser[ip] ] die\n");
            }
        }
    }
}


function check_new_server($server_flag, $servers, $old_servers)
{
    $diff = array_diff_key($servers, $old_servers);
    foreach($diff as $key => $ser) {
        //Send email (diff)
        outlog(__LINE__,"$server_flag [ name=$key,ip=$ser[ip] ] startup\n");
        sendmail("$server_flag [ name=$key,ip=$ser[ip] ] startup\n");
    }
}


function restart_server($server_flag, &$servers)
{
    foreach ($servers as $key => $ser) {
        if(start_remote_server($ser['ip'], SSH_USER, SSH_PASS, $server_flag)) {
            unset($servers[$key]);
        } else {
            ++$servers[$key]['disconnect'];
            if ($servers[$key]['disconnect'] >= CHECK_DISCONNECT_COUNT) {
                //Send email.
                outlog(__LINE__,"$server_flag [ name=$key,ip=$ser[ip] ] disconnect\n");
                unset($servers[$key]);
                sendmail("$server_flag [ name=$key,ip=$ser[ip] ] disconnect\n");
            }
        }
    }
}


function ReadServers($server_flag, $old_servers)
{
    $redis = new redis();
    $redis->connect(REDIS_SERVER, REDIS_PORT);
    $ret = array();
    $redis_name = $server_flag.'_servers';

    $servers = $redis->zrange($redis_name, 0, -1);
    foreach($servers as  $server) {
        $ret[$server]['ip'] = $redis->get($server);
        $ret[$server]['die'] = isset($old_servers[$server]['die']) ? $old_servers[$server]['die'] : 0;
        //$ret[$server]['disconnect'] = isset($old_servers[$server]['disconnect']) ? $old_servers[$server]['disconnect'] : 0;
    }
    $redis->close();

    return $ret;
}

function check_sys_function()
{
    $func_array = array(
        'pcntl_fork',
        'posix_kill',
        'fsockopen',
        'curl_init',
        'ssh2_connect',
        'base64_encode',
    );

    foreach($func_array as $name) {
    	if(!function_exists($name)) {
            outlog(__LINE__,"Function $name not exist.\n");
            return false;
        }
    }

    $class_array = array(
        'redis',
    );

    foreach($class_array as $name) {
        if(!class_exists($name)) {
            outlog(__LINE__,"Class $name not exist.\n");
            return false;
        }
    }

	return true;
}

function check_sys_cmd()
{
    $cmd_array = array(
        'mailx -V'
    );

    foreach($cmd_array as $name) {
        exec($name, $notuse, $ret);
        if ($ret != 0) {
            outlog(__LINE__,"Command $name not found.\n");
            return false;
        }
    }

    return true;
}

function broadcast_msg($msg)
{
    $socket = socket_create(AF_INET,SOCK_DGRAM,SOL_UDP);
    if(!$socket) {
        outlog(__LINE__,"Create udp server failed(broadcast_msg)\n");
        return false;
    }
    socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, 1);

    global $broadcast_ip;
    socket_sendto($socket, $msg, strlen($msg), MSG_DONTROUTE, $broadcast_ip, BROADCAST_PORT);
    socket_close($socket);
    return true;
}


function test_online_servers($socket, $local_status, &$online_servers)
{
    global $local_ip;
    $i = 0;
    $starttime = time();
    for (;;) {
        $buf = '';
        $from = '';
        $port = 0;
/*
        $readfds[] = $socket;
        if (false === socket_select($readfds, $writefds = null, $e = null, BROADCAST_RECV_TIMEOUT)) {
            foreach ($readfds as $key => $rfd) {
                if (@socket_recvfrom($socket, $buf, 128, 0, $from, $port) > 0) {
                    outlog(__LINE__,"Message($buf) from $from\n");
                    if (strstr($buf,MONITOR_FLAG.'run')) {
                        $online_servers[$from]['time'] = time();
                        $online_servers[$from]['status'] = 'run';
                    } else if (strstr($buf,MONITOR_FLAG.'idle')) {
                        $online_servers[$from]['time'] = time();
                        $online_servers[$from]['status'] = 'idle';
                    } else {
                        outlog(__LINE__,"Unkonw Message($buf) from $from\n");
                    }
                } else {
                    outlog(__LINE__,"timeout2\n");
                    if ($i++ >= 10) {
                        break 2;
                    }
                }
            }
        } else {
            outlog(__LINE__,"timeout\n");
        }
*/

        //socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array("sec"=>BROADCAST_RECV_TIMEOUT,"usec"=>0));
        if (@socket_recvfrom($socket, $buf, 128, 0, $from, $port) > 0) {
            //outlog(__LINE__,"Message($buf) from $from\n");
            if (strstr($buf,MONITOR_FLAG.'run')) {
                $online_servers[$from]['time'] = time();
                $online_servers[$from]['status'] = 'run';
            } else if (strstr($buf,MONITOR_FLAG.'idle')) {
                $online_servers[$from]['time'] = time();
                $online_servers[$from]['status'] = 'idle';
            } else {
                outlog(__LINE__,"Unkonw Message($buf) from $from\n");
            }
        } else {
            //outlog(__LINE__,$i."\n");
            if ($i++ >= 8) {
                break;
            }
        }

        if ((time()-$starttime) > BROADCAST_RECV_TIMEOUT * 8) {
            //outlog(__LINE__,"timeout\n");
            break;
        }

        //outlog(__LINE__,"from=$from,local_ip=$local_ip\n");

        if ($from == '') {
            broadcast_msg(MONITOR_FLAG . $local_status);
        }
    }
}


function get_run_servers(&$online_servers)
{
    $run_servers = array();
    $current_time = time();

    foreach($online_servers as $key => $value) {
        if ( ($current_time - $value['time']) > BROADCAST_SERVER_TIMEOUT) {
            //Send mail
            outlog(__LINE__,"Monitor($key) exit(timeout)\n");
            unset($online_servers[$key]);
            sendmail("Monitor($key) exit(timeout)\n");
        } else {
            if ($value['status'] == 'run') {
                $run_servers[$key] = $value;
            }
        }
    }

    return $run_servers;
}


function start_monitor()
{
    global $pids;
    global $check_servers;

    foreach($check_servers as $server_flag) {
        $pid = pcntl_fork();
        if ($pid == -1){
            outlog(__LINE__,"$server_flag cannot fork\n");
            exit(-1);
        } else if ($pid > 0){
            array_push($pids, $pid);
        } else if ($pid == 0) {
            outlog(__LINE__,"Start monitor ($server_flag)\n");
            $restart_servers = array();
            $servers = ReadServers($server_flag, NULL);
            for (;;) {
                $old_servers = $servers;
                $servers = ReadServers($server_flag, $servers);

                check_new_server($server_flag, $servers, $old_servers);

                check_server($server_flag, $servers, $restart_servers);
                restart_server($server_flag, $restart_servers);

                sleep(SERVER_TIMEOUT);
            }
            exit(0);
        }
    }
}

function stop_monitor()
{
    global $pids;

    foreach($pids as $pid) {
        posix_kill($pid, 9);
       /* pcntl_signal()*/
    }

    outlog(__LINE__,"start wait monitor out\n");
    foreach($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }
    $pids = array();
    outlog(__LINE__,"stop wait monitor out\n");
}


function monitor()
{
    global $local_ip;
    global $broadcast_ip;
    //$broadcast_ip = '0.0.0.0';
    $socket = socket_create(AF_INET,SOCK_DGRAM,SOL_UDP);
    if(!$socket) {
        outlog(__LINE__,"Create udp server failed(read_broadcast)\n");
        return false;
    }

    if (socket_bind($socket, $broadcast_ip, BROADCAST_PORT) === false) {
        outlog(__LINE__,"Bind failed(read_broadcast)\n");
        return false;
    }

    socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, 1);
    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, array("sec"=>BROADCAST_RECV_TIMEOUT,"usec"=>0));

    $online_servers = array();
    $local_status = 'idle';

    outlog(__LINE__,"CTI Monitor Start...\n");

    for(;;) {
        test_online_servers($socket, $local_status, $online_servers);
        $run_servers = get_run_servers($online_servers);
        $count = count($run_servers);

        if ($count >= 2) {
            ksort($run_servers);
            array_pop($run_servers);
            if (isset($run_servers[$local_ip])) {
                $local_status = 'idle';
                stop_monitor();
                outlog(__LINE__,"$local_ip stop monitor\n");
            }
        } else if($count == 0) {
            $local_run = false;
            if (count($online_servers) >= 2) {
                ksort($online_servers);
                $tmp = array_slice($online_servers, 0, 1);
                if (isset($tmp[$local_ip])) {
                    $local_run = true;
                }
            } else {
                $local_run = true;
            }

            if ($local_run) {
                $local_status = 'run';
                stop_monitor();
                start_monitor();
                outlog(__LINE__,"$local_ip start monitor\n");
            }
        } else {
            //Nonthing.
        }

        sleep(BROADCAST_MAIN_TIMEOUT);
    }

    return true;
}

if (!check_sys_function()) {
    exit(-1);
}

if (!check_sys_cmd()) {
    exit(-1);
}

if (!monitor()) {
    exit(-1);
}

outlog(__LINE__,"Monitor exit.\n");

?>

