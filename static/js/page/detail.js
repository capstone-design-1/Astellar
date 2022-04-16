let prev_attack_vector = [];
const socket = io();
const refresh_btn = document.getElementsByClassName("subdomain-refresh-btn");
const target_name = document.getElementsByName("target_name")[0].value;
const monitor_path = document.getElementsByName("monitor_path")[0].value;

window.onload = function(){
    if(refresh_btn.length != 0){
        refresh_btn[0].addEventListener("click", () => { searchSubdomain(target_name); });
    }

    socket.on('connect', function() {
        socket.emit('message', {"target": target_name, "monitor_path" : monitor_path});
    });
    socket.on('alive-check', function() {
        console.log("alive-check");
        socket.emit('alive-response', {"target": target_name});
    });
    socket.on("receive", function(res) {
        const data = res["data"];
        const key_list = Object.keys(data);

        console.log("[debug] ", data);

        for(let key of key_list){
            switch(key){
                case "packet_count":
                    setPacketCount(data[key]);
                    break;
                case "wappalyzer":
                    setWappalyzer(data[key]);
                    break;
                case "attack_vector":
                    setAttackVectorCount(data[key].length);
                    setAttackVector(data[key]);
                    break;
                case "modal":
                    setModalDetail(data[key]);
                    break;
                case "cve_modal":
                    setCveDetail(data[key]);
                    break;
            }
        }
    });

    function initSubdomain(target_name){
        try{
            fetch(`/detail/api/getSubdomain?target=${target_name}`)
            .then((res) => res.json())
            .then((data) => {
                if(data.result.length != 0){
                    setSubdomain(data);
                }
                else{
                    // alert("서브도메인이 없습니다.");
                }
            })
        }
        catch (error){
            alert("서브도메인 목록을 가져오는 과정에서 에러가 발생했습니다.");
            console.log(error);
        }
    }
    
    function searchSubdomain(target_name){
        const subdomain_selector = document.getElementsByClassName("subdomain-list")[0];
    
        try{
            subdomain_selector.innerHTML = `분석 중입니다. <div class="lds-ring lds-ring-green"><div></div></div>`;
    
            fetch(`/detail/api/subdomain?target=${target_name}`)
            .then((res) => res.json())
            .then((data) => {
                if(data.result.length != 0){
                    setSubdomain(data);
                }
                else{
                    // alert("서브도메인이 없습니다.");
                }
            })
        }
        catch (error){
            alert("서브도메인 목록을 가져오는 과정에서 에러가 발생했습니다.");
            console.log(error);
        }
    }


    function initStart(target_name){
        try{
            fetch(`/api/start?target=${target_name}`)
            .then((res) => res.json())
            .then((data) => {
                if(data["error"]){
                    alert(data["message"]);
                    // location.href='/';
                }
            })
        }
        catch{
            alert("proxify 프로그램이 실행되지 않았습니다.");
            // location.href='/';
        }
    }

    socket.emit("get_realtime_data", {"target": target_name});

    initSubdomain(target_name);
    initStart(target_name);
}

function setSubdomain(data){
    const subdomain_selector = document.getElementsByClassName("subdomain-list")[0];
    const update_time = document.getElementsByClassName("latest-update")[0];
    const html = `<div class="preview-item border-bottom">
                        <div class="preview-item-content d-sm-flex flex-grow">
                        <div class="flex-grow">
                            <h6 class="preview-subject"><a href="//{{subdomain}}" target="_blank">{{subdomain}}</a></h6>
                        </div>
                        <div class="mr-auto text-sm-right pt-2 pt-sm-0">
                            <p class="preview-subject">{{status_icon}} {{status_code}}</p>
                        </div>
                        </div>
                    </div>`;
    const red_circle_html = `<img src='/images/red-circle.png' width='15px;'>`;
    const green_circle_html = `<img src='/images/green-circle.png' width='15px;'>`;

    subdomain_selector.innerHTML = "";
    update_time.innerHTML = `Latest update: ${data.last_search_time}`;

    for(let i=0; i<data.result.length; i++){
        let circle = '';

        if(parseInt(data.result[i]["status_code"])){
            circle = (parseInt(data.result[i]["status_code"] / 100) <= 3) ? green_circle_html : red_circle_html;
        }
        else{
            circle = red_circle_html;
        }
        let template = html.replace(/{{subdomain}}/g, data.result[i]["site"])
                            .replace("{{status_icon}}", circle)
                            .replace("{{status_code}}", data.result[i]["status_code"]);

        subdomain_selector.innerHTML += template;
    }
}


function setPacketCount(packet_count){
    const selector = document.getElementsByClassName("packet-count");
    selector[0].innerHTML = packet_count;
}


function setWappalyzer(data){
    const selector = document.getElementsByClassName("wappalyer-result")[0];
    const detect_name_html = `<th class='table-wappalyzer'>{{name}}</th>`;
    const detect_detail_html = `<td>{{name}}</td>`;
    const html = `  <div class="col-sm-4 grid-margin">
                        <div class="card">
                            <div class="card-body">
                                <h3 class="card-title mb-1">🗺️ Server Info</h3>
                                <br>
                                <h4> {{target_name}} </h4>
                                <table class="table table-wappalyzer">
                                    <thead>
                                        <tr>
                                            {{detect_name}}
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            {{detect_detail}}
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>`;
    
    selector.innerHTML = "";

    for(let target_name of Object.keys(data)){

        let th_template = '';
        let td_template = '';
        for(let detect_name of Object.keys(data[target_name])){
            if (detect_name == "CPE"){
                continue;
            }
            th_template += detect_name_html.replace("{{name}}", detect_name);

            let tmp = [];
            for(let detect_detail of Object.keys(data[target_name][detect_name])){

                // 버전 정보가 없을 경우
                if(data[target_name][detect_name][detect_detail].length == 0){
                    tmp.push(detect_detail);
                }
                else{
                    tmp.push(`${detect_detail} / ${data[target_name][detect_name][detect_detail]}`);
                }
            }

            td_template += detect_detail_html.replace("{{name}}", tmp.join("<br><br>"));
        }

        let template = html.replace("{{target_name}}", target_name)
                            .replace("{{detect_name}}", th_template)
                            .replace("{{detect_detail}}", td_template);

        selector.innerHTML += template;
    }
}

function setAttackVectorCount(count){
    const selector = document.getElementsByClassName("vuln-count")[0];
    selector.innerHTML = count;
}

function setAttackVector(data){
    const selector = document.getElementsByClassName("attack-vector-result")[0].querySelector("tbody");

    if(prev_attack_vector.length == 0){
        selector.innerHTML = '';
    }
    if(prev_attack_vector.length == data.length){
        return;
    }
    const risk_info = `<div class="badge badge-outline-primary">Info</div>`;
    const risk_low = `<div class="badge badge-outline-success">Low</div>`;
    const risk_medium = `<div class="badge badge-outline-warning">Medium</div>`;
    const risk_high = `<div class="badge badge-outline-danger">High</div>`;
    const html = `<tr data-toggle="modal" data-target="#exampleModalCenter" onclick='setModal(this);' data-value='{{data-value}}'>
                    <td width="200px"> {{detect_name}} </td>
                    <td width="200px"> <div class="badge badge-success">{{method}}</div> </td>
                    <td width="200px"> <a href="{{full_url}}" target="_blank">{{url}}</a> </td>
                    <td width="200px"> {{vuln_parameter}} </td>
                    <td width="200px"> {{risk}} </td>
                    <td width="200px"> {{time}} </td>
                </tr>`;
    
    let template = ``;
    let count = 0;
    for(const analyze of data){
        if(prev_attack_vector.length > count){
            count++;
            continue;
        }

        let risk = ``;
        if(analyze["risk"] == "info"){
            risk = risk_info;
        }
        else if(analyze["risk"] == "low"){
            risk = risk_low;
        }
        else if(analyze["risk"] == "medium"){
            risk = risk_medium;
        }
        else{
            risk = risk_high;
        }

        let path = new URL(analyze["url"]);
        path = path.href.replace(path.origin, "");
        
        if(path.length > 35){
            path = path.substring(0, 35) + "...";
        }


        template += html.replace("{{detect_name}}", analyze["detect_name"])
                        .replace("{{method}}", analyze["method"])
                        .replace("{{full_url}}", escapeHTML(analyze["url"]))
                        .replace("{{url}}", escapeHTML(path))
                        .replace("{{vuln_parameter}}", analyze["vuln_parameter"])
                        .replace("{{risk}}", risk)
                        .replace("{{time}}", analyze["detect_time"])
                        .replace("{{data-value}}", escapeHTML(JSON.stringify(analyze)));
    }

    selector.innerHTML += template;
    prev_attack_vector = data;
}


function setModal(e){
    const data = JSON.parse(e.dataset.value);

    // modal_body.innerHTML = data["url"];

    socket.emit("get_packet_detail", {
        "target": target_name, 
        "file_path" : data["file_path"],
        "file_name" : data["file_name"]
    });
}


function setModalDetail(data, mode="request"){
    const modal_packet = document.getElementsByClassName("modal-packet")[0];
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
        setModalDetail(data);
    });
    document.getElementsByClassName("modal-response-btn")[0].addEventListener("click", () => {
        setModalDetail(data, "response");
    });
}


function setCve(){
    socket.emit("get_cve", {
        "target" : target_name
    })
}

function setCveDetail(data){
    const selector = document.getElementsByClassName("cve-detail")[0];
    const cve_name = `<li>{{cve_name}}</li>`;
    const cve_more_name = `<details>
                                <summary>More CVE</summary>
                                {{tmp_cve_name}}
                            </details>`;
    const html = `  <div class="col-6">
                        <h4 class="text-success"> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{{detect_name}} </h4>
                        <ul class="list-ticked">
                            {{cve_list}}
                        </ul>
                    </div>`;
    
    selector.innerHTML = "";

    for(let detect_name of Object.keys(data["cve"])){
        let cve_name_template = '';
        let tmp_template = '';

        for(let idx in data["cve"][detect_name]){
            if(idx >= 10){
                tmp_template += cve_name.replace("{{cve_name}}", data["cve"][detect_name][idx]);
            }
            else{
                cve_name_template += cve_name.replace("{{cve_name}}", data["cve"][detect_name][idx]);
            }
        }
        cve_name_template += cve_more_name.replace("{{tmp_cve_name}}", tmp_template);

        selector.innerHTML += html.replace("{{cve_list}}", cve_name_template)
                        .replace("{{detect_name}}", detect_name);
    }
}


function escapeHTML(data){
    return data.replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/'/g, "&apos;")
                .replace(/"/g, "&quot;");
}