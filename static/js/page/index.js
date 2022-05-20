const todo_delete_btn = document.getElementsByClassName("todo-delete");
const create_target = document.getElementsByClassName("create-target")[0];
let delete_target = '';

create_target.addEventListener("click", createTarget);

function addTodo() {
    const context = document.getElementsByClassName("todo-list-input")[0].value;

    fetch(`/api/add`, {
            method: "POST",
            body: JSON.stringify({ "context": context }),
            headers: {
                "Content-Type": "application/json"
            }
        })
        .then((res) => res.json())
        .then((data) => {
            if (data.result == "error")
                alert(data.message);
        })
}

function getTodo() {
    fetch(`/api/get`)
        .then((res) => res.json())
        .then((data) => {
            if (data.length == 0) return;

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

            for (let i = 0; i < data.length; i++) {
                let template = html.replace("{{context}}", data[i]["context"])
                    .replace("{{done}}", (data[i]["done"]) ? "checked" : "")
                    .replace("{{complete}}", (data[i]["done"]) ? "class='completed'" : "")
                    .replace("{{idx}}", data[i]["idx"]);
                todoListItem.append(template);
            }
        })
        .then(() => {
            for (let i = 0; i < todo_delete_btn.length; i++) {
                todo_delete_btn[i].addEventListener("click", (e) => {
                    deleteTodo(e);
                });
            }
        })
}

function deleteTodo(e) {
    const idx = e.target.parentElement.childNodes[5].value;

    fetch(`/api/delete`, {
            method: "POST",
            body: JSON.stringify({ "idx": idx }),
            headers: {
                "Content-Type": "application/json"
            }
        })
        .then((res) => res.json())
        .then((data) => {
            if (data.result == "error")
                alert(data.message);
        })
}

function updateState(e) {
    const idx = e.parent().parent().parent().find("input[name='idx']").val();
    let done = 0;

    if (e.attr('checked')) {
        done = 1;
    } else {
        done = 0;
    }

    fetch(`/api/update`, {
            method: "POST",
            body: JSON.stringify({ "idx": idx, "done": done }),
            headers: {
                "Content-Type": "application/json"
            }
        })
        .then((res) => res.json())
        .then((data) => {
            if (data.result == "error")
                alert(data.message);
        })
}

getTodo();


function createTarget() {
    const value = document.getElementsByName("create-target-value")[0].value;

    if (value.length == 0) return;

    if (value.indexOf("..") != -1) {
        alert(".. 문자열을 사용할 수 없습니다.");
        return;
    }
    if (value.indexOf("/") != -1) {
        alert("/ 문자열을 사용할 수 없습니다.");
        return;
    }

    try {
        fetch(`/api/create?target=${value}`)
            .then((res) => res.json())
            .then((data) => {
                if (data["result"] == "error") {
                    alert(data["message"]);
                    return;
                }

                // alert(data["message"]);
                location.href = '';
            })
    } catch {
        alert("target을 생성하는 과정에서 에러가 발생 했습니다.");
    }
}

function setDeleteTarget(e) {
    delete_target = e.dataset.value;
}

function targetDelete() {
    fetch(`/api/target/delete?target=${delete_target}`)
        .then(res => res.json())
        .then(data => {
            if (data["result"] == "error") {
                alert(data["message"]);
            } else {
                location.href = '';
            }
        })
}