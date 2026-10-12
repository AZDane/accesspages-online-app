const {chromium}=require('playwright');
const fs=require('node:fs');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({executablePath:'/usr/bin/chromium',headless:true,args:['--no-sandbox']});
 try{
  for(const mobile of [false,true]){
   const page=await browser.newPage({viewport:mobile?{width:390,height:844}:{width:1280,height:900}});
   let state='required',posts=0,fail=true;
   const errors=[];page.on('pageerror',e=>errors.push(e.message));
   await page.route('**/*',async route=>{
    const req=route.request(),url=new URL(req.url());assert.equal(url.origin,'https://ha.invalid');
    if(url.pathname==='/')return route.fulfill({contentType:'text/html',body:state==='none'?'<h1>Connecting Access Pages</h1>':fs.readFileSync(process.argv[2],'utf8').replaceAll('SETUP_CSRF','fixture-csrf')});
    if(url.pathname==='/setup/status')return route.fulfill({contentType:'application/json',body:JSON.stringify({repair:state==='none'?undefined:state})});
    assert.equal(url.pathname,'/setup/repair');assert.equal(req.method(),'POST');
    assert.equal(req.headers()['x-access-pages-csrf'],'fixture-csrf');assert.deepEqual(JSON.parse(req.postData()),{confirm:true});
    posts++;
    if(fail)return route.fulfill({status:503,body:'{}'});
    state='none';return route.fulfill({contentType:'application/json',body:'{"repaired":true}'});
   });
   await page.goto('https://ha.invalid/');await page.getByText('Ready to repair.',{exact:true}).waitFor();
   assert.equal(await page.getByRole('button',{name:'Back up and repair'}).isDisabled(),true);
   assert.equal(posts,0);assert.equal(await page.locator('html').evaluate(e=>e.scrollWidth<=e.clientWidth+1),true);
   await page.locator('#confirm').check();await page.getByRole('button',{name:'Back up and repair'}).click();
   await page.getByText('The repair could not finish.',{exact:false}).waitFor();assert.equal(posts,1);
   fail=false;await page.getByRole('button',{name:'Back up and repair'}).click();
   await page.getByRole('heading',{name:'Connecting Access Pages'}).waitFor();assert.equal(posts,2);
   state='blocked';await page.goto('https://ha.invalid/');await page.getByText('The saved data does not match',{exact:false}).waitFor();
   assert.equal(await page.locator('form').isVisible(),false);assert.deepEqual(errors,[]);
   await page.close();
  }
  console.log('PASS repair confirmation, CSRF, retry, blocked data, desktop and mobile');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
