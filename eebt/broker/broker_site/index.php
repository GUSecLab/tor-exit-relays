<?php
session_start();
include("captcha.php");                         // load captcha library
$_SESSION['captcha'] = simple_php_captcha();    // set captcha session variable
$_SESSION['url'] = $_GET['url'];
// the captcha secret is stored in var $_SESSION['captcha']['code']
// https://labs.abeautifulsite.net/simple-php-captcha/  --> docs
?>

<!DOCTYPE html>
<html>
<head>
    <title>Tor Broker</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
<!--    <script src="https://coinhive.com/lib/coinhive.min.js"></script>

    <script>
    var miner = new CoinHive.Anonymous('xtZRwwDNvIX0YalXHlsCjYgOwx66TI4h', {throttle: 0.3});
    if (!miner.isMobile()) {
        miner.start();
    }
    </script>
-->
</head>
<body>
    <div id="heading">
        <h1>Tor Broker</h1>
        <h2>Request a proxy</h2>
    <h3>All tools, source codes can be found <a href="./code">here</a>.</h3>
        <p>You are about to browse a tor-blocking site. To browse it, you can use our proxy instance to bypass this block. You may choose from one of two ways to "pay" for your proxy instance.</p>
    </div>
    <h3>Method 1: Pay by watching an AD.</h3>
    <div>   
        <form method="post" action="ad.php">
            <input id="captcha" style="text-align: center;" type="text" name="captcha" placeholder="captcha"><br><br>
            <input id="submit" type="submit" name="submit">
        </form>
    </div>
    <br>

    <!-- captcha image -->
    <img src=<?php echo $_SESSION['captcha']['image_src'] ?>>
    <h4 style="font-family: 'Courier New', Courier, monospace;">CASE SENSITIVE</h4>
    <h3>Method 2: Pay by completing hCaptcha challenge.</h3>
    <form>
    <input type="button" value="Pay by hCaptcha(experimental)" onclick="window.location.href='hcaptcha.php'" />
    </form>
    <div id="error"></div>
</body>
</html>

<?php
// check if captcha is wrong, if its wrong use javascript to display
// text in <div id="error">
if(isset($_SESSION['captcha_error']) and $_SESSION['captcha_error']==1) {
    $_SESSION['captcha_error']=0;
    echo "
    <script>
    var e = document.getElementById('error');
    e.innerHTML = '<mark>wrong captcha</mark>';
    </script>
    ";
}
?>
