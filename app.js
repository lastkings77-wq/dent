/* Стомато PWA. Данные шифруются AES-GCM и хранятся в IndexedDB.
   Не собирает аналитику и не отправляет данные на сервер. */
"use strict";
(() => {
  const $ = (s, root=document) => root.querySelector(s);
  const $$ = (s, root=document) => [...root.querySelectorAll(s)];
  const DB_NAME = "stomato-secure-v1", DB_VERSION = 1, STORE = "vault", VAULT_KEY = "primary";
  const te = new TextEncoder(), td = new TextDecoder();
  let db, cryptoKey, vaultSalt, state, activeView = "dashboard", selectedPatientId = null;
  let noticeTimer;
  const money = n => new Intl.NumberFormat("ru-RU", {style:"decimal", maximumFractionDigits:2}).format(Number(n)||0) + " сум";
  const dateText = v => { if(!v) return "—"; const d = new Date(v); return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("ru-RU",{dateStyle:"short",timeStyle: v.includes("T") ? "short" : undefined}); };
  const today = () => { const d = new Date(); d.setMinutes(d.getMinutes()-d.getTimezoneOffset()); return d.toISOString().slice(0,10); };
  const uid = () => crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36)+Math.random().toString(36).slice(2);
  const esc = v => String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  const validDate = s => !!s && !Number.isNaN(new Date(s).getTime());
  const number = (v, label, min=0) => { const n=Number(v); if(!Number.isFinite(n)||n<min) throw new Error(`${label}: введите число не меньше ${min}.`); return n; };
  function notify(msg, bad=false){ const el=$("#notice"); el.textContent=msg; el.classList.toggle("bad",bad); el.hidden=false; clearTimeout(noticeTimer); noticeTimer=setTimeout(()=>el.hidden=true,5000); }
  function openDB(){ return new Promise((resolve,reject)=>{ const req=indexedDB.open(DB_NAME,DB_VERSION); req.onupgradeneeded=()=>{ if(!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE); }; req.onsuccess=()=>resolve(req.result); req.onerror=()=>reject(new Error("Не удалось открыть локальное хранилище.")); }); }
  function getVault(){ return new Promise((resolve,reject)=>{ const tx=db.transaction(STORE,"readonly"), req=tx.objectStore(STORE).get(VAULT_KEY); req.onsuccess=()=>resolve(req.result||null); req.onerror=()=>reject(new Error("Не удалось прочитать локальные данные.")); }); }
  function putVault(value){ return new Promise((resolve,reject)=>{ const tx=db.transaction(STORE,"readwrite"); tx.objectStore(STORE).put(value,VAULT_KEY); tx.oncomplete=()=>resolve(); tx.onerror=()=>reject(new Error("Не удалось сохранить данные. Проверьте свободное место на устройстве.")); tx.onabort=()=>reject(new Error("Сохранение отменено.")); }); }
  async function deriveKey(pass,salt){ const material=await crypto.subtle.importKey("raw",te.encode(pass),"PBKDF2",false,["deriveKey"]); return crypto.subtle.deriveKey({name:"PBKDF2",salt,iterations:310000,hash:"SHA-256"},material,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]); }
  async function encryptState(obj){ const iv=crypto.getRandomValues(new Uint8Array(12)); const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},cryptoKey,te.encode(JSON.stringify(obj))); return {version:1,iv:Array.from(iv),cipher:Array.from(new Uint8Array(cipher)),updatedAt:new Date().toISOString()}; }
  async function decryptState(record){ try { const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(record.iv)},cryptoKey,new Uint8Array(record.cipher)); return JSON.parse(td.decode(plain)); } catch { throw new Error("Неверный пароль или повреждённые данные. Данные не изменены."); } }
  const blankState = () => ({schema:1, clinics:[], patients:[], appointments:[], treatments:[], transactions:[]});
  async function save(){ const record=await encryptState(state); await putVault({salt:Array.from(vaultSalt),payload:record}); }
  async function boot(){
    try {
      if(!window.crypto?.subtle || !window.indexedDB){ $("#lock-error").textContent="Этот браузер не поддерживает необходимые функции безопасности. Откройте приложение в актуальном Safari через HTTPS."; $("#unlock-button").disabled=true; return; }
      db=await openDB();
      const vault=await getVault();
      $("#lock-hint").textContent=vault ? "Введите пароль, заданный при первом запуске. Пароль не хранится в приложении." : "При первом запуске придумайте пароль не короче 10 символов. Данные будут зашифрованы на этом устройстве. Потерянный пароль восстановить нельзя.";
      $("#unlock-button").textContent=vault ? "Разблокировать" : "Создать защищённое хранилище";
      $("#unlock-form").addEventListener("submit",unlock);
    } catch(e){ $("#lock-error").textContent=e.message||"Ошибка инициализации."; }
  }
  async function unlock(ev){
    ev.preventDefault(); const pass=$("#passphrase").value; const err=$("#lock-error"); err.textContent="";
    if(pass.length<10){err.textContent="Пароль должен содержать не менее 10 символов.";return;}
    $("#unlock-button").disabled=true;
    try {
      const vault=await getVault();
      if(vault){ cryptoKey=await deriveKey(pass,new Uint8Array(vault.salt)); state=await decryptState(vault.payload); }
      else { const salt=crypto.getRandomValues(new Uint8Array(16)); cryptoKey=await deriveKey(pass,salt); state=blankState(); await putVault({salt:Array.from(salt),payload:await encryptState(state)}); }
      if(!state || state.schema!==1 || !Array.isArray(state.patients)) throw new Error("Структура хранилища не распознана.");
      $("#lock-screen").hidden=true; $("#main-screen").hidden=false; $("#passphrase").value=""; render();
    } catch(e){ err.textContent=e.message||"Не удалось разблокировать хранилище."; cryptoKey=null; }
    finally { $("#unlock-button").disabled=false; }
  }
  async function persist(){ try { await save(); render(); } catch(e){ notify(e.message||"Ошибка сохранения.",true); throw e; } }
  function lock(){ cryptoKey=null; vaultSalt=null; state=null; selectedPatientId=null; $("#main-screen").hidden=true; $("#lock-screen").hidden=false; $("#passphrase").value=""; $("#lock-error").textContent=""; }
  function clinicName(id){ return state.clinics.find(c=>c.id===id)?.name || "Клиника не выбрана"; }
  function patientName(id){ const p=state.patients.find(p=>p.id===id); return p ? p.name : "Пациент удалён"; }
  function clinicOptions(value=""){ return `<option value="">— выберите клинику —</option>`+state.clinics.map(c=>`<option value="${c.id}" ${c.id===value?"selected":""}>${esc(c.name)}</option>`).join(""); }
  function patientOptions(value=""){ return `<option value="">— выберите пациента —</option>`+state.patients.slice().sort((a,b)=>a.name.localeCompare(b.name,"ru")).map(p=>`<option value="${p.id}" ${p.id===value?"selected":""}>${esc(p.name)}</option>`).join(""); }
  function card(title,body,extra=""){return `<article class="item"><div class="spread"><div class="item-title">${title}</div>${extra}</div>${body}</article>`;}
  function empty(msg){return `<div class="empty">${esc(msg)}</div>`;}
  function render(){ if(!state)return; renderDashboard(); renderPatients(); renderCalendar(); renderFinance(); renderSettings(); showView(activeView); }
  function showView(name){ activeView=name; $$(".view").forEach(v=>v.hidden=v.id!==`view-${name}`); $$(".tab").forEach(b=>b.classList.toggle("active",b.dataset.view===name)); }
  function renderDashboard(){
    const date=today(), todays=state.appointments.filter(a=>a.datetime.slice(0,10)===date && a.status!=="Отменён");
    const dayIncome=state.transactions.filter(t=>t.kind==="income"&&t.date===date).reduce((s,t)=>s+t.amount,0);
    const month=new Date().toISOString().slice(0,7), monthIncome=state.transactions.filter(t=>t.kind==="income"&&t.date.startsWith(month)).reduce((s,t)=>s+t.amount,0);
    const debts=state.transactions.filter(t=>t.kind==="debt").reduce((s,t)=>s+t.amount,0);
    $("#view-dashboard").innerHTML=`<h2>Обзор</h2><div class="grid">
      <div class="stat"><div class="muted small">Записи сегодня</div><div class="num">${todays.length}</div></div>
      <div class="stat"><div class="muted small">Поступления сегодня</div><div class="num">${money(dayIncome)}</div></div>
      <div class="stat"><div class="muted small">Поступления за месяц</div><div class="num">${money(monthIncome)}</div></div>
      <div class="stat"><div class="muted small">Учтённые долги</div><div class="num">${money(debts)}</div></div>
    </div><div class="spread" style="margin-top:22px"><h3>Ближайшие записи</h3><button class="primary" data-action="add-appointment">+ Запись</button></div>
    <div class="list">${todays.length?todays.sort((a,b)=>a.datetime.localeCompare(b.datetime)).map(a=>card(`${esc(a.datetime.slice(11,16))} · ${esc(patientName(a.patientId))}`,`<p>${esc(clinicName(a.clinicId))} · ${esc(a.reason||"Без комментария")}</p>`,`<span class="pill">${esc(a.status)}</span>`)).join(""):empty("На сегодня записей нет.")}</div>
    <div class="panel" style="margin-top:14px"><h3>Начало работы</h3><p class="subtle">Сначала добавьте клинику в разделе «Клиники и данные», затем пациента и запись. Финансовые операции сохраняются отдельно и не выводят автоматически рассчитанный процент из записи.</p></div>`;
  }
  function renderPatients(){
    const root=$("#view-patients");
    root.innerHTML=`<div class="spread"><h2>Пациенты</h2><button class="primary" data-action="add-patient">+ Пациент</button></div>
    <div class="toolbar"><input id="patient-search" placeholder="Поиск по имени или телефону" aria-label="Поиск пациентов"></div><div id="patient-list" class="list"></div>`;
    const fill=()=>{ const q=($("#patient-search").value||"").toLocaleLowerCase("ru"); const arr=state.patients.filter(p=>(p.name+" "+p.phone).toLocaleLowerCase("ru").includes(q)).sort((a,b)=>a.name.localeCompare(b.name,"ru")); $("#patient-list").innerHTML=arr.length?arr.map(p=>card(esc(p.name),`<p>${esc(p.phone||"Телефон не указан")}</p><p>${esc(p.birthDate?("Дата рождения: "+p.birthDate):"")}</p>`,`<button class="secondary compact" data-action="open-patient" data-id="${p.id}">Открыть</button>`)).join(""):empty("Пациенты не найдены."); };
    $("#patient-search").addEventListener("input",fill); fill();
  }
  const upper=[18,17,16,15,14,13,12,11,21,22,23,24,25,26,27,28];
  const lower=[48,47,46,45,44,43,42,41,31,32,33,34,35,36,37,38];
  function odontogramHtml(map={}){ return `<div class="tooth-note">Нажмите на зуб, чтобы указать заметку/состояние. Это свободная запись, не автоматическая диагностика.</div><div class="tooth-grid">${upper.map(n=>`<button type="button" class="tooth ${map[n]?"selected":""}" data-tooth="${n}" title="${esc(map[n]||"Без заметки")}">${n}</button>`).join("")}</div><div class="tooth-grid">${lower.map(n=>`<button type="button" class="tooth ${map[n]?"selected":""}" data-tooth="${n}" title="${esc(map[n]||"Без заметки")}">${n}</button>`).join("")}</div>`; }
  function renderCalendar(){
    const day=$("#calendar-date")?.value||today();
    $("#view-calendar").innerHTML=`<div class="spread"><h2>Записи</h2><button class="primary" data-action="add-appointment">+ Запись</button></div><div class="field"><label for="calendar-date">Дата</label><input type="date" id="calendar-date" value="${esc(day)}"></div><div id="appointment-list" class="list"></div>`;
    const fill=()=>{ const d=$("#calendar-date").value; const arr=state.appointments.filter(a=>a.datetime.slice(0,10)===d).sort((a,b)=>a.datetime.localeCompare(b.datetime)); $("#appointment-list").innerHTML=arr.length?arr.map(a=>card(`${esc(a.datetime.slice(11,16))} · ${esc(patientName(a.patientId))}`,`<p>${esc(clinicName(a.clinicId))} · ${esc(a.reason||"Без комментария")}</p><p>${esc(a.note||"")}</p>`,`<div class="row"><span class="pill">${esc(a.status)}</span><button class="secondary compact" data-action="edit-appointment" data-id="${a.id}">Изменить</button></div>`)).join(""):empty("На эту дату записей нет."); };
    $("#calendar-date").addEventListener("change",fill); fill();
  }
  function renderFinance(){
    const income=state.transactions.filter(t=>t.kind==="income").reduce((s,t)=>s+t.amount,0);
    const expense=state.transactions.filter(t=>t.kind==="expense").reduce((s,t)=>s+t.amount,0);
    const debt=state.transactions.filter(t=>t.kind==="debt").reduce((s,t)=>s+t.amount,0);
    const earnedByClinic=state.transactions.filter(t=>t.kind==="income").reduce((acc,t)=>{const c=state.clinics.find(x=>x.id===t.clinicId); const share=(c?.share??100)/100; acc[t.clinicId]=(acc[t.clinicId]||0)+t.amount*share; return acc;},{});
    $("#view-finance").innerHTML=`<div class="spread"><h2>Финансы</h2><button class="primary" data-action="add-transaction">+ Операция</button></div>
      <div class="grid"><div class="stat"><div class="muted small">Поступления</div><div class="num">${money(income)}</div></div><div class="stat"><div class="muted small">Расходы</div><div class="num">${money(expense)}</div></div><div class="stat"><div class="muted small">Долги (внесённые)</div><div class="num">${money(debt)}</div></div><div class="stat"><div class="muted small">Доход после процента</div><div class="num">${money(Object.values(earnedByClinic).reduce((a,b)=>a+b,0)-expense)}</div></div></div>
      <p class="subtle">Процент клиники применяется к поступлениям этой клиники. Расходы вычитаются целиком из общего результата; если материалы должны относиться к конкретной клинике, указывайте клинику при создании операции.</p>
      <h3 style="margin-top:22px">Операции</h3><div class="list">${state.transactions.slice().sort((a,b)=>(b.date+b.createdAt).localeCompare(a.date+a.createdAt)).map(t=>card(`${esc(t.kind==="income"?"Поступление":t.kind==="expense"?"Расход":"Долг")} · ${money(t.amount)}`,`<p>${esc(t.date)} · ${esc(clinicName(t.clinicId))} · ${esc(patientName(t.patientId))}</p><p>${esc(t.description||"Без описания")}</p>`,`<button class="danger compact" data-action="delete-transaction" data-id="${t.id}">Удалить</button>`)).join("")||empty("Операций пока нет.")}</div>`;
  }
  function renderSettings(){
    $("#view-settings").innerHTML=`<h2>Клиники и данные</h2><div class="panel"><div class="spread"><h3>Клиники и процент клиники</h3><button class="primary" data-action="add-clinic">+ Клиника</button></div><p class="subtle">Укажите долю клиники в процентах. Например, если ваша доля 40%, укажите долю клиники 60%. Доля применяется только в финансовом отчёте.</p><div class="list">${state.clinics.map(c=>card(esc(c.name),`<p>Доля клиники: ${c.share}% · Ваша доля: ${100-c.share}%</p>`,`<button class="secondary compact" data-action="edit-clinic" data-id="${c.id}">Изменить</button>`)).join("")||empty("Добавьте первую клинику.")}</div></div>
      <div class="panel" style="margin-top:14px"><h3>Резервная копия</h3><p class="subtle">Экспорт создаёт зашифрованную резервную копию. Сохраните её в защищённом месте. Для импорта потребуется пароль текущего хранилища и пароль копии.</p><div class="toolbar"><button class="secondary" data-action="export">Экспортировать копию</button><button class="secondary" data-action="import">Импортировать копию</button></div><p class="subtle">Не отправляйте копию третьим лицам: она содержит медицинские и финансовые данные.</p></div>
      <div class="panel" style="margin-top:14px"><h3>Безопасность и обслуживание</h3><p class="subtle">Данные шифруются AES-GCM-256; ключ выводится из пароля PBKDF2-SHA-256. Приложение не отправляет записи на сервер. Используйте длинный уникальный пароль, блокировку iPhone и защищённую резервную копию.</p><button class="danger" data-action="wipe">Удалить все данные с устройства</button></div>`;
  }
  function showModal(title,body,saveLabel="Сохранить"){
    $("#modal-content").innerHTML=`<h2>${esc(title)}</h2>${body}`;
    $("#modal-save").textContent=saveLabel; $("#modal-save").hidden=!saveLabel;
    $("#modal").showModal();
  }
  function closeModal(){ $("#modal").close(); }
  function field(label,name,type="text",value="",attrs=""){return `<div class="field"><label for="f-${name}">${esc(label)}</label><input id="f-${name}" name="${name}" type="${type}" value="${esc(value)}" ${attrs}></div>`;}
  function area(label,name,value="",attrs=""){return `<div class="field"><label for="f-${name}">${esc(label)}</label><textarea id="f-${name}" name="${name}" ${attrs}>${esc(value)}</textarea></div>`;}
  function selectField(label,name,options,value=""){return `<div class="field"><label for="f-${name}">${esc(label)}</label><select id="f-${name}" name="${name}">${options}</select></div>`;}
  function formData(){return Object.fromEntries(new FormData($("#modal-form")).entries());}
  function hookModal(handler){ $("#modal-form").onsubmit=async e=>{e.preventDefault();try{await handler(formData());closeModal();}catch(err){notify(err.message||"Проверьте введённые данные.",true);}}; }
  function addClinic(existing=null){
    const c=existing||{name:"",share:50}; showModal(existing?"Изменить клинику":"Новая клиника",field("Название клиники","name","text",c.name,"required maxlength='80'")+field("Доля клиники, %","share","number",c.share,"required min='0' max='100' step='0.1'"));
    hookModal(async d=>{const name=d.name.trim();if(!name)throw new Error("Укажите название клиники.");const share=number(d.share,"Доля клиники",0);if(share>100)throw new Error("Доля клиники не может превышать 100%.");if(existing){Object.assign(existing,{name,share});}else state.clinics.push({id:uid(),name,share});await persist();});
  }
  function addPatient(existing=null){
    const p=existing||{name:"",phone:"",birthDate:"",allergies:"",anamnesis:"",notes:"",odontogram:{}};
    showModal(existing?"Карточка пациента":"Новый пациент",field("ФИО","name","text",p.name,"required maxlength='120'")+field("Телефон","phone","tel",p.phone,"maxlength='40'")+field("Дата рождения","birthDate","date",p.birthDate,"")+area("Аллергии","allergies",p.allergies)+area("Анамнез","anamnesis",p.anamnesis)+area("Заметки","notes",p.notes)+`<hr><h3>Зубная формула FDI</h3><div id="modal-odontogram">${odontogramHtml(p.odontogram)}</div><p id="tooth-note-label" class="tooth-note">Выберите зуб, чтобы добавить или изменить заметку.</p>`);
    const map={...p.odontogram}; $$("#modal-odontogram [data-tooth]").forEach(b=>b.addEventListener("click",()=>{const n=b.dataset.tooth;const old=map[n]||"";const val=prompt(`Зуб ${n}: заметка/состояние (пусто — очистить)`,old);if(val===null)return;if(val.trim())map[n]=val.trim().slice(0,200);else delete map[n];b.classList.toggle("selected",!!map[n]);b.title=map[n]||"Без заметки";b.setAttribute("aria-label",`Зуб ${n}: ${map[n]||"без заметки"}`);$("#tooth-note-label").textContent=`Зуб ${n}: ${map[n]||"заметка удалена"}`;}));
    hookModal(async d=>{const name=d.name.trim();if(!name)throw new Error("Введите ФИО пациента.");if(d.birthDate&&!validDate(d.birthDate))throw new Error("Проверьте дату рождения.");const data={name,phone:d.phone.trim(),birthDate:d.birthDate,allergies:d.allergies.trim(),anamnesis:d.anamnesis.trim(),notes:d.notes.trim(),odontogram:map};if(existing)Object.assign(existing,data);else state.patients.push({id:uid(),createdAt:new Date().toISOString(),...data});await persist();});
  }
  function openPatient(id){
    const p=state.patients.find(x=>x.id===id);if(!p)return;selectedPatientId=id;
    const visits=state.treatments.filter(t=>t.patientId===id).sort((a,b)=>b.date.localeCompare(a.date));
    const appointments=state.appointments.filter(a=>a.patientId===id).sort((a,b)=>b.datetime.localeCompare(a.datetime));
    showModal(p.name,`<div class="row"><button type="button" class="secondary" id="edit-this-patient">Редактировать карточку</button><button type="button" class="secondary" id="add-treatment">+ История лечения</button><button type="button" class="danger" id="delete-this-patient">Удалить пациента</button></div>
      <div class="panel" style="margin-top:12px"><p><b>Телефон:</b> ${esc(p.phone||"—")}</p><p><b>Дата рождения:</b> ${esc(p.birthDate||"—")}</p><p><b>Аллергии:</b> ${esc(p.allergies||"—")}</p><p><b>Анамнез:</b> ${esc(p.anamnesis||"—")}</p><p><b>Заметки:</b> ${esc(p.notes||"—")}</p><h3>Зубная формула</h3>${odontogramHtml(p.odontogram)}</div><h3 style="margin-top:14px">История лечения</h3><div class="list">${visits.map(t=>card(`${esc(t.date)} · ${esc(t.procedure)}`,`<p>${esc(clinicName(t.clinicId))} · ${money(t.cost)}</p><p>${esc(t.notes||"")}</p>`)).join("")||empty("История лечения пока пустая.")}</div><h3 style="margin-top:14px">Записи</h3><div class="list">${appointments.map(a=>card(`${esc(dateText(a.datetime))}`,`<p>${esc(clinicName(a.clinicId))} · ${esc(a.reason||"")}</p><p>${esc(a.status)}</p>`)).join("")||empty("Записей пока нет.")}</div>`,null);
    $("#edit-this-patient").onclick=()=>{closeModal();addPatient(p);};
    $("#add-treatment").onclick=()=>{closeModal();addTreatment(p.id);};
    $("#delete-this-patient").onclick=async()=>{if(!confirm("Удалить пациента? Его записи и история лечения останутся, но связь с карточкой будет потеряна."))return;state.patients=state.patients.filter(x=>x.id!==id);await persist();closeModal();};
    $$("#modal-content [data-tooth]").forEach(b=>b.addEventListener("click",()=>{const n=b.dataset.tooth;const val=prompt(`Зуб ${n}: заметка/состояние`,p.odontogram?.[n]||"");if(val===null)return;if(!p.odontogram)p.odontogram={};if(val.trim())p.odontogram[n]=val.trim().slice(0,200);else delete p.odontogram[n];persist().then(()=>openPatient(id)).catch(()=>{});}));
  }
  function addTreatment(patientId){
    showModal("Добавить лечение",selectField("Клиника","clinicId",clinicOptions(),state.clinics[0]?.id||"")+field("Дата","date","date",today(),"required")+field("Процедура","procedure","text","","required maxlength='160'")+field("Стоимость","cost","number","0","required min='0' step='0.01'")+area("Заметки","notes"));
    hookModal(async d=>{if(!d.clinicId)throw new Error("Сначала добавьте клинику и выберите её.");if(!d.procedure.trim())throw new Error("Укажите процедуру.");if(!validDate(d.date))throw new Error("Укажите корректную дату.");state.treatments.push({id:uid(),patientId,clinicId:d.clinicId,date:d.date,procedure:d.procedure.trim(),cost:number(d.cost,"Стоимость",0),notes:d.notes.trim()});await persist();});
  }
  function addAppointment(existing=null){
    if(!state.clinics.length||!state.patients.length){notify("Сначала добавьте клинику и пациента.",true);return;}
    const a=existing||{patientId:"",clinicId:state.clinics[0].id,datetime:today()+"T10:00",reason:"",note:"",status:"Запланирован"};
    showModal(existing?"Изменить запись":"Новая запись",selectField("Пациент","patientId",patientOptions(a.patientId),a.patientId)+selectField("Клиника","clinicId",clinicOptions(a.clinicId),a.clinicId)+field("Дата и время","datetime","datetime-local",a.datetime,"required")+field("Причина визита","reason","text",a.reason,"maxlength='160'")+area("Заметки","note",a.note)+selectField("Статус","status",["Запланирован","Пришёл","Не пришёл","Отменён"].map(s=>`<option ${s===a.status?"selected":""}>${s}</option>`).join(""),a.status));
    hookModal(async d=>{if(!d.patientId||!state.patients.some(p=>p.id===d.patientId))throw new Error("Выберите существующего пациента.");if(!d.clinicId||!state.clinics.some(c=>c.id===d.clinicId))throw new Error("Выберите существующую клинику.");if(!validDate(d.datetime))throw new Error("Проверьте дату и время.");const data={patientId:d.patientId,clinicId:d.clinicId,datetime:d.datetime,reason:d.reason.trim(),note:d.note.trim(),status:d.status};if(existing)Object.assign(existing,data);else state.appointments.push({id:uid(),createdAt:new Date().toISOString(),...data});await persist();});
  }
  function addTransaction(){
    if(!state.clinics.length){notify("Сначала добавьте клинику.",true);return;}
    showModal("Финансовая операция",selectField("Тип","kind",`<option value="income">Поступление от пациента</option><option value="expense">Расход</option><option value="debt">Долг пациента (сумма к получению)</option>`,"income")+selectField("Клиника","clinicId",clinicOptions(state.clinics[0].id),state.clinics[0].id)+selectField("Пациент (необязательно)","patientId",patientOptions(),"")+field("Дата","date","date",today(),"required")+field("Сумма, сум","amount","number","0","required min='0.01' step='0.01'")+field("Описание","description","text","","maxlength='200'"));
    hookModal(async d=>{if(!["income","expense","debt"].includes(d.kind))throw new Error("Неверный тип операции.");if(!d.clinicId||!state.clinics.some(c=>c.id===d.clinicId))throw new Error("Выберите клинику.");if(d.patientId&&!state.patients.some(p=>p.id===d.patientId))throw new Error("Выбранный пациент не найден.");if(!validDate(d.date))throw new Error("Проверьте дату.");state.transactions.push({id:uid(),kind:d.kind,clinicId:d.clinicId,patientId:d.patientId, date:d.date,amount:number(d.amount,"Сумма",0.01),description:d.description.trim(),createdAt:new Date().toISOString()});await persist();});
  }
  async function exportBackup(){
    const pass=prompt("Придумайте пароль для зашифрованной копии (не менее 10 символов). Не используйте пароль приложения.");if(pass===null)return;if(pass.length<10)throw new Error("Пароль копии должен быть не короче 10 символов.");
    const salt=crypto.getRandomValues(new Uint8Array(16)), key=await deriveKey(pass,salt), iv=crypto.getRandomValues(new Uint8Array(12));
    const cipher=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,te.encode(JSON.stringify(state)));
    const backup={format:"stomato-backup",version:1,salt:Array.from(salt),iv:Array.from(iv),cipher:Array.from(new Uint8Array(cipher)),createdAt:new Date().toISOString()};
    const blob=new Blob([JSON.stringify(backup)],{type:"application/json"}), url=URL.createObjectURL(blob), a=document.createElement("a");a.href=url;a.download=`stomato-backup-${today()}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1500);notify("Зашифрованная копия подготовлена. Проверьте, что файл действительно сохранился.");
  }
  async function importBackup(){
    const input=document.createElement("input");input.type="file";input.accept=".json,application/json";
    input.onchange=async()=>{try{const file=input.files?.[0];if(!file)return;if(file.size>20*1024*1024)throw new Error("Файл больше 20 МБ.");const b=JSON.parse(await file.text());if(b.format!=="stomato-backup"||b.version!==1||!Array.isArray(b.salt)||!Array.isArray(b.iv)||!Array.isArray(b.cipher))throw new Error("Это не резервная копия Стомато или формат не поддерживается.");const pass=prompt("Введите пароль резервной копии.");if(pass===null)return;const key=await deriveKey(pass,new Uint8Array(b.salt));let parsed;try{const plain=await crypto.subtle.decrypt({name:"AES-GCM",iv:new Uint8Array(b.iv)},key,new Uint8Array(b.cipher));parsed=JSON.parse(td.decode(plain));}catch{throw new Error("Не удалось расшифровать копию: проверьте пароль или файл.");}validateImported(parsed);if(!confirm("Импорт заменит все текущие данные. Сначала экспортируйте копию текущих данных. Продолжить?"))return;state=parsed;await persist();notify("Копия импортирована.");}catch(e){notify(e.message||"Ошибка импорта.",true);}};
    input.click();
  }
  function validateImported(s){if(!s||s.schema!==1||!["clinics","patients","appointments","treatments","transactions"].every(k=>Array.isArray(s[k])))throw new Error("Структура резервной копии некорректна.");if(s.clinics.length>1000||s.patients.length>100000||s.appointments.length>500000||s.transactions.length>500000||s.treatments.length>500000)throw new Error("В резервной копии слишком много записей.");}
  async function wipe(){if(!confirm("Удалить ВСЕ данные? Это действие нельзя отменить. Сначала экспортируйте резервную копию, если она нужна."))return;if(!confirm("Последнее подтверждение: удалить пациентов, записи, лечение, клиники и финансы?"))return;await putVault(null);const tx=db.transaction(STORE,"readwrite");tx.objectStore(STORE).delete(VAULT_KEY);tx.oncomplete=()=>{notify("Данные удалены.");lock();};tx.onerror=()=>notify("Не удалось удалить хранилище.",true);}
  async function handleAction(btn){
    const a=btn.dataset.action,id=btn.dataset.id;
    try{
      if(a==="add-clinic")addClinic();
      else if(a==="edit-clinic")addClinic(state.clinics.find(c=>c.id===id));
      else if(a==="add-patient")addPatient();
      else if(a==="open-patient")openPatient(id);
      else if(a==="add-treatment")addTreatment(id);
      else if(a==="add-appointment")addAppointment();
      else if(a==="edit-appointment")addAppointment(state.appointments.find(x=>x.id===id));
      else if(a==="add-transaction")addTransaction();
      else if(a==="delete-transaction"){if(confirm("Удалить финансовую операцию?")){state.transactions=state.transactions.filter(t=>t.id!==id);await persist();}}
      else if(a==="export")await exportBackup();
      else if(a==="import")await importBackup();
      else if(a==="wipe")await wipe();
    }catch(e){notify(e.message||"Операция не выполнена.",true);}
  }
  document.addEventListener("click",e=>{const tab=e.target.closest("[data-view]");if(tab){showView(tab.dataset.view);return;}const btn=e.target.closest("[data-action]");if(btn)handleAction(btn);});
  $("#lock-now").addEventListener("click",lock);
  $("#modal").addEventListener("click",e=>{if(e.target===$("#modal"))closeModal();});
  $("#modal-form").addEventListener("click",e=>{if(e.target.matches("[data-action]"))handleAction(e.target);});
  if("serviceWorker" in navigator && location.protocol!=="file:") navigator.serviceWorker.register("./sw.js").catch(()=>{});
  boot();
})();