
var url = new URL(window.location.href);
var url_to_jump = url.searchParams.get("url");
console.log(url_to_jump);
document.getElementById("demo").innerHTML = url_to_jump;