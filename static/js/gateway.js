'use strict'

function getAvailableSolutionKits(callback) {
    var settings = {
        "url": "/api/v1/solutionkits",
        "method": "GET"
      };
      
      $.ajax(settings).done(function (response) {
            callback(response);
      });
}


function getGateways (callback) {
    var settings = {
        "url": "/api/v1/gateways",
        "method": "GET"
      };
      
      $.ajax(settings).done(function (response) {
          
            callback(response);
      });
}


//setTimeout(function (){
function openWebSocket(callback){
      let socket = new WebSocket("ws://localhost:8080/ws");

      socket.onopen = function(e) {
        socket.send("My name is John");
      };
      
      socket.onmessage = function(event) {
        alert(`[message] Data received from server: ${event.data}`);
        callback(event)
      };
      
      socket.onclose = function(event) {
        if (event.wasClean) {
          alert(`[close] Connection closed cleanly, code=${event.code} reason=${event.reason}`);
        } else {
          // e.g. server process killed or network down
          // event.code is usually 1006 in this case
          alert('[close] Connection died');
        }
      };
      
      socket.onerror = function(error) {
        alert(`[error] ${error}`);
        console.log(error)
      };    
}




