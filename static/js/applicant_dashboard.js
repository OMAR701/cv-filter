const form = document.querySelector(".icon"),
fileInput = document.querySelector(".input-file"),
progressArea = document.querySelector(".progress-area");
form.addEventListener("click", () =>{
  fileInput.click();
});

fileInput.onchange = ({target})=>{
    let file = target.files[0];
    if(file){
      let fileName = file.name;
      uploadFile(fileName)
    }
  }

 function uploadFile(name) {
    let progressHTML = `<li class="applicant_row">
                            <i class="fas fa-file-alt"></i>
                            <div class="applicant_content>
                                <div class="up_file_details">
                                    <span class="up_file_name">${name} • Uploaded</span>
                                </div>
                            </div>
                            <i class="fas fa-check"></i>
                        </li>`;

    progressArea.innerHTML = progressHTML;
 }