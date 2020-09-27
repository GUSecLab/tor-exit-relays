<?php 
function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}



session_start();
//TODO: implement server side hcaptcha verification according to doc here: https://hcaptcha.com/docs#server
if (isset($_POST['h-captcha-response']) && strlen($_POST['h-captcha-response']))
{
    $ws_key_cgi = generateRandomString(16);
    $_SESSION['ws_key_browser'] = generateRandomString(16);
    exec('cgi/start_spawn '.$ws_key_cgi.' '.$_SESSION['ws_key_browser'].' &');
    $ws_key_cgi = undefined;
} else {
    echo "You must complete hCaptcha challenges first";
    session_unset();
    session_destroy();
    header('refresh:1;url=hcaptcha.php');
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Tor Broker</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <script type="text/javascript">
        var ws_key_browser =  "<?php echo $_SESSION['ws_key_browser'] ?>";
        var conn = new WebSocket('ws://' + window.location.hostname + '/ws2');
        conn.onopen = function(e) {
            console.log("Connection established!");
        };
        conn.onmessage = function(e) {
            console.log(e.data);
            msg = JSON.parse(e.data)
            if (msg.operation === 'identify')
            {
                conn.send(JSON.stringify({"operation": "identify", "side":"browser", "ws_key": ws_key_browser}));
                console.log(JSON.stringify({"operation": "identify", "side":"browser", "ws_key": ws_key_browser}));
            }
            else if(msg.operation === 'update')
            {
                try {
                        bridge_info = JSON.parse(msg.msg);
                        var origin =  "<?php echo $_SESSION['url'] ?>";
                        var url = "http://127.0.0.1:12346/?user=" + bridge_info.user + '?pass=' + bridge_info.password + '?host=' + bridge_info.host + '?port=10182?type=tcp?origin=' + origin
                        window.location.replace(url);
                    }
                    catch(err) {
                        var node = document.createElement("LI");
                        var textnode = document.createTextNode(msg.msg);
                        node.appendChild(textnode);
                        document.getElementById("WSState").appendChild(node);
                    }
            }
            else
            {
                console.log(msg)
                //conn.close()
            }
        };

    </script>
</head>
<body>
    <div id="heading">
        <h2>Please allow some time for proxy spawn</h2>
        <ul id="WSState">
            <li>Requesting Instance...</li>
        </ul>
        <p>You will be redirected back once our proxy is ready.</p>
    </div>
</body>
</html>
