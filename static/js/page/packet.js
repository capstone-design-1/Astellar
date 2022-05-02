const socket = io();
let get_url_tree = 0;
const target_name = document.getElementsByName("target_name")[0].value;

function startPacket(bool){
    if(bool){
        get_url_tree = setInterval(() => {
            const target_name = document.getElementsByName("target_name")[0].value;
            socket.emit("get_url_tree", {"target" : target_name});
        }, 2000);
    }
    else{
        clearInterval(get_url_tree);
    }
}

window.onload = function() {
    socket.emit("get_url_tree", {"target" : target_name});
    startPacket(true);

    socket.on("receive", (res) => {
        const data = res["data"];
        const key_list = Object.keys(data);

        for(let key of key_list){
            console.log(key);
            switch(key){
                case "url_tree":
                    console.log(data[key]);
                    initUrlTree(data[key]);
                    break;
                case "packet":
                    console.log(data[key]);
                    showPacket(data[key]);
            }
        }
    })
}


function initUrlTree(data){
    const selector = document.getElementsByClassName("url-tree-result")[0];

    selector.innerHTML = `분석 중입니다. <div class="lds-ring lds-ring-green"><div></div></div>`;

    let template = ``;
    for(let key of Object.keys(data)){
        template += `<h4>${key}</h4>` + createUrlTree(data[key]) + "<br>";
    }

    selector.innerHTML = template;
}

function createUrlTree(data){
    
    const li_html = `<li> {{result_li}}</li>`;
    const ul_html = `<ul> {{result_ul}} </ul>`;
    const folder_html = `<input type="checkbox" id="{{folder_name}}-{{time}}">
                            <label for="{{folder_name}}-{{time}}">{{folder_name}}</label>`;
    const file_html = `<input type="checkbox" id="{{file_name}}-{{time}}" data-value="{{packet_name}}">
                        <label for="{{file_name}}-{{time}}" class="lastTree" data-value="{{packet_name}}" onclick="getPacket(this)">{{file_name}}</label><br>`;
    
    let template = ``;
    try{
        for(let node of data){
            let path_tmp = '';
            if(node["path"].length >= 20){
                path_tmp = node["path"].substr(0, 20) + "...";
            }
            else{
                path_tmp = node["path"]
            }
    
            let folder_tmp = folder_html.replace(/{{folder_name}}/g, path_tmp)
                                        .replace(/{{time}}/g, Math.random().toString(36));
            let file_tmp = ``;
            for(let packet of node["packet"]){
                file_tmp += file_html.replace(/{{file_name}}/g, packet["params"])
                                    .replace(/{{time}}/g, Math.random().toString(36))
                                    .replace(/{{packet_name}}/g, packet["file_name"]);
            }
    
            let sub_folder_tmp = ul_html.replace("{{result_ul}}", createUrlTree(node["sub_path"]) + file_tmp);
            template += li_html.replace("{{result_li}}", folder_tmp + sub_folder_tmp);
    
        }
    }
    catch{
        template = `분석 중입니다. <div class="lds-ring lds-ring-green"><div></div></div>`;
        
    }

    return template;
}


function getPacket(e){
    const target_name = document.getElementsByName("target_name")[0].value;
    const target_path = document.getElementsByName("monitor_path")[0].value;
    const packet_name = e.dataset.value;

    socket.emit("get_packet", {
        "target" : target_name,
        "file_path" : target_path,
        "file_name" : packet_name
    })
}

function showPacket(data, mode="request"){
    const modal_packet = document.getElementsByClassName("packet-detail")[0];
    let packet = `<button type="button" class="btn btn-outline-info btn-fw modal-request-btn">Request</button>
                            <button type="button" class="btn btn-outline-info btn-fw modal-response-btn">Response</button><Br><Br>`;

    if(mode == "request"){
        packet += `<code>${data[mode]["method"]}</code> ${data[mode]["url"]} ${data[mode]["http_protocol"] }<br>`
    }
    else if(mode == "response"){
        packet += `${data[mode]["http_protocol"]} <code>${data[mode]["status_code"]}</code> ${data[mode]["reason"] }<br>`
    }

    for(let header_key in data[mode]["header"]){
        packet += `<code>${header_key}</code>: ${escapeHTML(data[mode]["header"][header_key])}<br>`;
    }
    packet += `<br>${escapeHTML(data[mode]["body"])}`;

    modal_packet.innerHTML = packet;

    document.getElementsByClassName("modal-request-btn")[0].addEventListener("click", () => {
        showPacket(data);
    });
    document.getElementsByClassName("modal-response-btn")[0].addEventListener("click", () => {
        showPacket(data, "response");
    });
}

function searchPacket(value){
    const target_path = document.getElementsByName("monitor_path")[0].value;
    const target_name = document.getElementsByName("target_name")[0].value;
    
    if(value.length == 0){
        socket.emit("get_url_tree", {"target" : target_name});
        startPacket(true);
    }
    else{
        startPacket(false);
        socket.emit("search_packet", {"target" : target_name, "data" : value, "target_path" : target_path});
    }
}

function escapeHTML(data){
    return data.replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/'/g, "&apos;")
                .replace(/"/g, "&quot;");
}