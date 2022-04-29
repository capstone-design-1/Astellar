const socket = io();
let check = 1;
window.onload = function() {
    const target_name = document.getElementsByName("target_name")[0].value;

    socket.on("receive", (res) => {
        const data = res["data"];
        const key_list = Object.keys(data);

        for(let key of key_list){
            switch(key){
                case "url_tree":
                    if(check == 0){
                        break;
                    }
                    check = 0;
                    console.log(data[key]);
                    document.getElementsByClassName("url-tree-result")[0].innerHTML = createUrlTree(data[key]);
                    break;
            }
        }
    })

    socket.emit("get_url_tree", {"target" : target_name});
}

function createUrlTree(data){
    const selector = document.getElementsByClassName("url-tree-result")[0];
    const li_html = `<li> {{result_li}}</li>`;
    const ul_html = `<ul> {{result_ul}} </ul>`;
    const folder_html = `<input type="checkbox" id="{{folder_name}}-{{time}}">
                            <label for="{{folder_name}}-{{time}}">{{folder_name}}</label>`;
    const file_html = `<input type="checkbox" id="{{file_name}}-{{time}}" data-value="{{packet_name}}">
                        <label for="{{file_name}}-{{time}}" class="lastTree" data-value="{{packet_name}}">{{file_name}}</label><br>`;
    
    let template = ``;
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

    return template;
}
