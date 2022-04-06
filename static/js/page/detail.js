window.onload = function(){
    const refresh_btn = document.getElementsByClassName("subdomain-refresh-btn");

    if(refresh_btn.length != 0){
        refresh_btn[0].addEventListener("click", getSubdomain);
    }


    function getSubdomain(){
        const target_name = document.getElementsByName("target_name")[0].value;
        const subdomain_selector = document.getElementsByClassName("subdomain-list")[0];
        const html = `<div class="preview-item border-bottom">
                            <div class="preview-item-content d-sm-flex flex-grow">
                            <div class="flex-grow">
                                <h6 class="preview-subject"><a href="//{{subdomain}}">{{subdomain}}</a></h6>
                            </div>
                            <div class="mr-auto text-sm-right pt-2 pt-sm-0">
                                <p class="preview-subject">{{status_icon}} {{status_code}}</p>
                            </div>
                            </div>
                        </div>`;
        const red_circle_html = `<img src='/images/red-circle.png' width='15px;'>`;
        const green_circle_html = `<img src='/images/green-circle.png' width='15px;'>`;

        try{
            subdomain_selector.innerHTML = "분석중 입니다.";

            fetch(`/detail/api/subdomain?target=${target_name}`)
            .then((res) => res.json())
            .then((data) => {
                if(data.result.length != 0){
                    subdomain_selector.innerHTML = "";
                    
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
                else{
                    alert("서브도메인이 없습니다.");
                }
            })
        }
        catch (error){
            alert("서브도메인 목록을 가져오는 과정에서 에러가 발생했습니다.");
            console.log(error);
        }
    }

    var socket = io();
    socket.on('connect', function() {
        const target = document.getElementsByName("target_name")[0].value;
        socket.emit('message', {"target": target});
    });
}