const loadData = async () => {
    const data = await fetchData()
    if (!data) {
        console.log("data is not valid " + data)
        setForm(true)
    } else {
        console.log("data is valid " + data)
        setForm(false)
        setData(data)
    }
}

const setForm = (visible) => {
    const state = visible ? "block" : "none"
    document.getElementById("form-placeholder").style.display = state
}

const setData = (data) => {
    const placeholder = document.getElementById("data-placeholder")
    const { role, name } = data.identity.traits
    placeholder.innerHTML = `<div><h4>${name.first.toUpperCase()}, you have the following role</h4><span>${role}</span></div>`
}

const fetchData = async() => {
    const response = await fetch("/api/session", {
        headers: {
        "Content-Type": "application/json",
        },
        method: "GET",
    });

    if (response.status === 401) {
        return Promise.resolve(false)
    }

    if (!response.ok) {      
        alert("get data failed!")
        return Promise.resolve(false)
    }

    return await response.json()
}


const login = async (e) => {
    e.preventDefault();
    const form = document.querySelector('form');
    const data = Object.fromEntries(new FormData(form).entries())
    await postLogin(data.email, data.password)    
    location.reload()
}

const postLogin = async(email, password) => {
    const formData = new URLSearchParams()
    formData.append("email", email)
    formData.append("password", password)
  
    const response = await fetch("/login", {
      body: formData,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        credentials: "include",
      },
      method: "POST",
    });
  
    if (!response.ok) {      
      alert("login failed!")
      return
    }
}