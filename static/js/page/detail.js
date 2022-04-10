window.onload = function(){
    const refresh_btn = document.getElementsByClassName("subdomain-refresh-btn");
    const target_name = document.getElementsByName("target_name")[0].value;
    const monitor_path = document.getElementsByName("monitor_path")[0].value;

    if(refresh_btn.length != 0){
        refresh_btn[0].addEventListener("click", () => { searchSubdomain(target_name); });
    }

    var socket = io();
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

        if(key_list.length == 0){
            clearInterval(get_realtime_data);
            alert("서버 에러가 발생했습니다. 재시작 해주세요.");
            return;
        }

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
            }
        }
    });

    
    const get_realtime_data = setInterval(()=> {
        socket.emit("get_realtime_data", {"target": target_name});
    }, 3000);

    initSubdomain(target_name);

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
    const html = `  <div class="col-sm-3 grid-margin">
                        <div class="card">
                            <div class="card-body">
                                <h3>{{tech_name}}</h3>
                                <div class="row">
                                    <div class="col-8 col-sm-12 col-xl-8 my-auto">
                                        <div class="d-flex d-sm-block d-md-flex align-items-center">
                                            <h5 class="mb-0">{{detect_list}}</h5>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>`;
    const detect_list = `<h5 class="mb-0">{{detect_name}}</h5>`;
    
    selector.innerHTML = "";
    let template = '';

    for(let key of Object.keys(data)){
        let detect_list_template = '';

        for(let detect_name of Object.keys(data[key])){
            detect_list_template += detect_list.replace("{{detect_name}}", detect_name + " " + data[key][detect_name]);
        }

        template += html.replace("{{tech_name}}", key).replace("{{detect_list}}", detect_list_template);
    }

    selector.innerHTML = template;
}

function setAttackVectorCount(count){
    const selector = document.getElementsByClassName("vuln-count")[0];
    selector.innerHTML = count;
}

function setAttackVector(data){
    const selector = document.getElementsByClassName("attack-vector-result")[0].querySelector("tbody");
    const risk_low = `<div class="badge badge-outline-success">Low</div>`;
    const risk_medium = `<div class="badge badge-outline-warning">Medium</div>`;
    const risk_high = `<div class="badge badge-outline-danger">High</div>`;
    const html = `<tr>
                    <td width="200px"> {{detect_name}} </td>
                    <td width="200px"> <div class="badge badge-success">{{method}}</div> </td>
                    <td width="200px"> {{url}} </td>
                    <td width="200px"> {{vuln_parameter}} </td>
                    <td width="200px"> {{risk}} </td>
                </tr>`;
    
    let template = ``;

    for(const analyze of data){
        let risk = ``;
        if(analyze["risk"] == "low"){
            risk = risk_low;
        }
        else if(analyze["risk"] == "medium"){
            risk = risk_medium;
        }
        else{
            risk = risk_high;
        }

        template += html.replace("{{detect_name}}", analyze["detect_name"])
                        .replace("{{method}}", analyze["method"])
                        .replace("{{url}}", analyze["url"])
                        .replace("{{vuln_parameter}}", analyze["vuln_parameter"])
                        .replace("{{risk}}", risk);
    }

    selector.innerHTML = template;
    
}