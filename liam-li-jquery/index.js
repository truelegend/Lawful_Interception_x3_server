
// $(document).ready(function(){
//     $(".btn").click(function(){
//         alert("you clicked!");
//     });
// })


function WebSocketTest(socketURL)
{   
    var websocket = null;
    var n = 0;
    var recv_conclusion = false;
    if ("WebSocket" in window){
        websocket = new WebSocket(socketURL);
    }
    else {
        alert('Not support websocket');
    }
    websocket.onerror = function(event){  
        alert("error");  
    };
    websocket.onopen = function(){  
        $("#textarea-output").text("Connected with WS Server")
    }
    websocket.onmessage = function(event){  
        n++;
        if(event.data.search("End of the story") != -1){
            websocket.close();
            return;
        }
        if(event.data.search("===============") != -1){
            console.log("rev is true");
            recv_conclusion = true;
            $("#textarea-output").text($("#textarea-output").text() + "\n" + event.data);
            return;
        }
        if(n <= 90 || recv_conclusion == true){
             //console.log("log event: "+n);
            $("#textarea-output").text($("#textarea-output").text() + event.data);      
        }
        else{
            if(n%8 == 0){
                $("#textarea-output").text($("#textarea-output").text() + ".");
            }
        }
        //$("#textarea-output").text(n++)      
        //console.log($("#textarea-output").text() + event.data)
    }
    websocket.onclose = function(event){  
    } 
}

// $(document).on("click","#btn-start",function(){
//     $.get("start",function(data,textStatus){
//         $("#p-output").html(data);
//         poll_loop = setInterval(function(){
//          $("#p-output").load("increment");},1000)
//     })

$(document).on("click","#btn-start",function(){
    $.get("start",function(data,textStatus){
        $("#textarea-output").text(data);
        WebSocketTest('ws://' + document.location.hostname + ":9001")
    })
})
