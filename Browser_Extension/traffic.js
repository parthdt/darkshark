chrome.webRequest.onBeforeRequest.addListener(
    function(details) {
      var websites = ['https://www.amazon.com/', 'https://www.flipkart.com/','https://www.myntra.com/', 'https://www.codechef.com/', 'https://www.hackerrank.com/', 'https://www.hackerearth.com/'];

	var url;
	for(url of websites){
		fetch(url)
        	    .then(response => response.json())
        	    .then(data => console.log(data));
	}  
    },
    {urls: ["<all_urls>"]},
    ["requestBody"]
  );
