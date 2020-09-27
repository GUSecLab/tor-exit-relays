function saveOptions(e) {
    e.preventDefault();
    browser.storage.sync.set({
        host: document.querySelector("#host").value
    });
}

function restoreOptions() {

    function setCurrentChoice(result) {
        document.querySelector("#host").value = result.host || "";
    }

    function onError(error) {
        console.log(`Error: ${error}`);
    }

    var getting = browser.storage.sync.get("host");
    getting.then(setCurrentChoice, onError);
}

document.addEventListener("DOMContentLoaded", restoreOptions);
document.querySelector("form").addEventListener("submit", saveOptions);