chrome.runtime.sendMessage({todo: "showPageAction"});

chrome.runtime.onMessage.addListener(function(request, sender, sendResponse){
    if(request.todo == "changeColor"){
        var addColor = request.clickedColor;
        document.body.style.backgroundColor = addColor;
    }
});