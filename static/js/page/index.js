const todo_btn = document.getElementsByClassName("todo-list-add-btn");
const todo_delete_btn = document.getElementsByClassName("todo-delete");

if(todo_btn.length != 0){
    todo_btn[0].addEventListener("click", addTodo);
}

function addTodo(){
    const context = document.getElementsByClassName("todo-list-input")[0].value;
    
    fetch(`/todo/api/add`, {
        method: "POST",
        body: JSON.stringify({"context" : context}),
        headers: {
            "Content-Type" : "application/json"
        }
    })
    .then((res) => res.json())
    .then((data) => {
        if(data.result == "error")
            alert(data.message);
    })
}

function getTodo(){
    fetch(`/todo/api/get`)
    .then((res) => res.json())
    .then((data) => {
        console.log(data);
        if(data.length == 0) return;

        const todoListItem = $('.todo-list');
        const html = `  <li {{complete}}>
                            <div class="form-check">
                                <label class="form-check-label">
                                    <input class="checkbox" type="checkbox" {{done}}>{{context}}
                                    <i class="input-helper"></i>
                                </label>
                            </div>
                            <i class="remove mdi mdi-close-circle-outline todo-delete"></i>
                            <input type="hidden" name="idx" value="{{idx}}">
                        </li>`;

        for(let i=0; i<data.length; i++){
            let template = html.replace("{{context}}", data[i]["context"])
                                .replace("{{done}}", (data[i]["done"]) ? "checked" : "")
                                .replace("{{complete}}", (data[i]["done"]) ? "class='completed'" : "")
                                .replace("{{idx}}", data[i]["idx"]);
            todoListItem.append(template);
        }
    })
    .then(() => {
        for(let i=0; i<todo_delete_btn.length; i++){
            todo_delete_btn[i].addEventListener("click", (e) => {
                deleteTodo(e);
            });
        }
    })
}

function deleteTodo(e){
    const idx = e.target.parentElement.childNodes[5].value;

    fetch(`/todo/api/delete`, {
        method: "POST",
        body: JSON.stringify({"idx" : idx}),
        headers: {
            "Content-Type" : "application/json"
        }
    })
    .then((res) => res.json())
    .then((data) => {
        if(data.result == "error")
            alert(data.message);
    })
}

function updateState(e){
    const idx = e.parent().parent().parent().find("input[name='idx']").val();
    let done = 0;

    if(e.attr('checked')){
        done = 1;
    }
    else{
        done = 0;
    }

    fetch(`/todo/api/update`, {
        method: "POST",
        body: JSON.stringify({"idx" : idx, "done" : done}),
        headers: {
            "Content-Type" : "application/json"
        }
    })
    .then((res) => res.json())
    .then((data) => {
        if(data.result == "error")
            alert(data.message);
    })
}

getTodo();