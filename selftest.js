/* Federation Bench self test. Loaded by index.html only when the URL carries
   ?selftest, so none of this reaches a normal page load. Runs in the browser on
   purpose: about thirty of these checks need getComputedStyle, DOMParser, real
   click dispatch, or SRI actually loading, none of which Node has without
   pulling in jsdom and a dependency tree this project deliberately avoids.

   The application's own script is a classic script, so its top-level const and
   function declarations are in the global lexical scope and directly usable
   here. Nothing needs to be exported.

   Every case below is a bug that shipped once. Add to it when you fix
   something, rather than checking by hand. */
/* ==================== self test ====================
   There is no build step and no test runner, so the regression checks live in
   the page. Open index.html?selftest, or call selfTest() from the console.
   Nothing here executes on a normal load. Every case below is a bug that
   shipped once, so add to it when you fix something rather than checking by
   hand. */
async function selfTest(){
  const results=[]; let fails=0, skips=0;
  const eq =(got,want)=> got===want ? true : `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`;
  const has=(hay,re)=> re.test(hay) ? true : `expected to find ${re}`;
  const not=(hay,re)=> re.test(hay) ? `did not expect ${re}` : true;
  const t=async (name,fn)=>{
    let got; try{ got=await fn(); }catch(e){ got=`threw ${e&&e.name||'Error'}: ${e&&e.message||e}`; }
    const state = got===true ? 'pass'
      : (typeof got==='string'&&got.startsWith('skip')) ? 'skip' : 'fail';
    if(state==='fail') fails++; else if(state==='skip') skips++;
    results.push([state,name,got===true?'ok':String(got)]);
  };

  /* The check CLAUDE.md asks for by hand: every element lookup in the script
     must resolve after a markup change. The page's own script is read out of
     the DOM, so this needs no tooling. External scripts, including this file,
     have empty textContent, so only application code is scanned and the suite
     cannot match its own strings. */
  await t('every element lookup resolves to a real element', ()=>{
    const src=Array.from(document.querySelectorAll('script')).map(s=>s.textContent).join('\n');
    const ids=Array.from(new Set(Array.from(src.matchAll(/\$\('([A-Za-z0-9_-]+)'\)/g), m=>m[1])));
    if(ids.length<20) return `only found ${ids.length} lookups, so this check has stopped working`;
    const missing=ids.filter(id=>!document.getElementById(id));
    return missing.length ? `${missing.length} missing: ${missing.join(', ')}` : true;
  });

  /* ---- item 1: thumbprint encodings. Graph sends base64, the preferred-key
     field is hex, PowerShell sends a byte array. ---- */
  const bytes=Array.from({length:20},(_,i)=>i);
  const hex=bytes.map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
  const b64=btoa(String.fromCharCode.apply(null,bytes));
  await t('thumbHex decodes base64 to hex',        ()=>eq(thumbHex(b64),hex));
  await t('thumbHex passes hex through',           ()=>eq(thumbHex(hex),hex));
  await t('thumbHex uppercases lowercase hex',     ()=>eq(thumbHex(hex.toLowerCase()),hex));
  await t('thumbHex strips colons from hex',       ()=>eq(thumbHex(hex.match(/../g).join(':')),hex));
  await t('thumbHex reads a PowerShell byte array',()=>eq(thumbHex(bytes),hex));
  await t('thumbHex handles null and empty',       ()=>eq(thumbHex(null)+thumbHex(''),''));
  await t('thumbHex does not throw on garbage',    ()=>eq(typeof thumbHex('!!! nope !!!'),'string'));

  const spCert=(offsetDays,keyId,preferred)=>({displayName:'Test',appId:'a',id:'sp1',preferredSingleSignOnMode:'saml',
    preferredTokenSigningKeyThumbprint:preferred===undefined?hex:preferred,
    keyCredentials:[{usage:'Verify',type:'AsymmetricX509Cert',customKeyIdentifier:keyId===undefined?b64:keyId,
      endDateTime:new Date(Date.now()+offsetDays*86400000).toISOString()}]});
  await t('expired active certificate fails the cert segment', ()=>eq(analyseServicePrincipal(spCert(-30)).st.cert,'fail'));
  await t('certificate inside 45 days warns',                  ()=>eq(analyseServicePrincipal(spCert(20)).st.cert,'warn'));
  await t('healthy certificate passes',                        ()=>eq(analyseServicePrincipal(spCert(300)).st.cert,'pass'));
  await t('active certificate is labelled as active',          ()=>has(analyseServicePrincipal(spCert(300)).certRows,/Active certificate/));
  await t('displayed thumbprint is hex, never base64',         ()=>not(analyseServicePrincipal(spCert(300)).certRows,/<code>[A-Za-z0-9+/]{20,}={1,2}<\/code>/));
  await t('unreported preferred key does not read as healthy', ()=>eq(analyseServicePrincipal(spCert(-30,undefined,'')).st.cert,'warn'));
  await t('thumbprint mismatch does not read as healthy',      ()=>eq(analyseServicePrincipal(spCert(-30,btoa(String.fromCharCode.apply(null,Array(20).fill(171))))).st.cert,'warn'));

  /* ---- item 2: group-inherited assignments ---- */
  const spReq={id:'sp1',displayName:'Test',appRoleAssignmentRequired:true};
  const asg=(list,ctx,sp)=>analyseAssignments(list,sp||spReq,ctx);
  await t('assignment not required is not a finding',   ()=>eq(asg([],null,{id:'sp1',appRoleAssignmentRequired:false}).st.assigned,undefined));
  await t('direct assignment passes',                   ()=>eq(asg([{resourceId:'sp1'}],null).st.assigned,'pass'));
  /* Observed live: the user-side list can carry a group's assignment, with
     principalType 'Group'. Calling that "directly" names the wrong object.
     Fixture names here are invented. Never paste a real group, app or account
     name out of a tenant into this file: it is a public repository. */
  await t('a group-typed hit is not labelled as direct', ()=>{
    const r=asg([{resourceId:'sp1',principalType:'Group',principalDisplayName:'Example Staff Group'}],null);
    if(r.st.assigned!=='pass') return `verdict ${r.st.assigned}, expected pass`;
    if(/directly/.test(r.rows)) return 'reported a group assignment as direct';
    if(!/Example Staff Group/.test(r.rows)) return 'did not name the group';
    return has(r.rows,/through a group/);
  });
  await t('a user-typed hit is still labelled as direct', ()=>
    has(asg([{resourceId:'sp1',principalType:'User',principalDisplayName:'Jane'}],null).rows,/yes, directly/));
  await t('a hit with no principalType is treated as direct', ()=>
    has(asg([{resourceId:'sp1'}],null).rows,/yes, directly/));
  await t('empty direct list alone never fails',        ()=>eq(asg([],null).st.assigned,'warn'));
  await t('empty direct list explains group blindness', ()=>has(asg([],null).rows,/direct<\/b> assignments only/));
  await t('group-inherited assignment passes',          ()=>eq(asg([],{userId:'u1',groupIds:['g1','g2'],assigned:new Set(['g2']),complete:true,truncated:false}).st.assigned,'pass'));
  await t('service-principal-side direct match passes', ()=>eq(asg([],{userId:'u1',groupIds:[],assigned:new Set(['u1']),complete:true,truncated:false}).st.assigned,'pass'));
  await t('genuinely unassigned user fails',            ()=>eq(asg([],{userId:'u1',groupIds:['g1'],assigned:new Set(['g9']),complete:true,truncated:false}).st.assigned,'fail'));

  /* A 200 can carry a partial membership list, notably for hidden-membership
     groups, and nothing in the response flags it. The verdict stays fail, but
     it must show its working rather than assert a certainty it lacks. */
  const unassigned=(groups,principals)=>asg([],{userId:'u1',
    groupIds:groups, assigned:new Set(principals), complete:true, truncated:false});
  await t('the fail note states how many groups and principals were checked', ()=>{
    const r=unassigned(['g1','g2'],['g9']);
    if(!/2 groups/.test(r.rows)) return 'did not state the group count';
    return has(r.rows,/1 principal\b/);
  });
  await t('counts are singular when there is one of them', ()=>
    has(unassigned(['g1'],['g9']).rows,/1 group\b/));
  await t('the fail note names an authority instead of asserting certainty', ()=>
    has(unassigned(['g1'],['g9']).rows,/Users and groups/));
  await t('the fail note warns that hidden group membership is invisible', ()=>
    has(unassigned(['g1'],['g9']).rows,/hidden is not returned/));
  await t('zero visible groups gets a stronger caveat', ()=>{
    const r=unassigned([],['g9']);
    if(!/No group memberships were visible/.test(r.rows)) return 'no caveat when nothing was visible';
    return has(r.rows,/conclusion is unsafe/);
  });
  await t('the stronger caveat is absent when groups were visible', ()=>
    not(unassigned(['g1'],['g9']).rows,/No group memberships were visible/));
  await t('the verdict is still fail, not softened to warn', ()=>
    eq(unassigned([],['g9']).st.assigned,'fail'));
  await t('only a complete check may cite AADSTS50105', ()=>not(asg([],{userId:'u1',groupIds:['g1'],assigned:new Set(['g9']),complete:false,truncated:true}).rows,/AADSTS50105/));
  await t('truncated paging degrades to warn, not fail',()=>eq(asg([],{userId:'u1',groupIds:['g1'],assigned:new Set(['g9']),complete:false,truncated:true}).st.assigned,'warn'));

  /* ---- g() header plumbing ----
     Some endpoints return complete results only when ConsistencyLevel is sent.
     A partial result that looks whole is exactly the failure this tool exists
     to avoid, so the header must survive the helper. */
  const withFetch=async (handler, fn)=>{
    const realFetch=window.fetch, realToken=window.token;
    const calls=[];
    try{
      window.token=async()=>'fake-token';
      window.fetch=async(u,opts)=>{ calls.push({url:u, headers:(opts||{}).headers||{}}); return handler(); };
      const out=await fn();
      return {out, calls};
    } finally { window.fetch=realFetch; window.token=realToken; }
  };
  await t('g() passes custom headers through and keeps Authorization', async ()=>{
    const {calls}=await withFetch(()=>({ok:true, json:async()=>({value:[]})}),
      ()=>g('/x',{ConsistencyLevel:'eventual'}));
    if(!calls.length) return 'fetch was never called';
    const h=calls[0].headers;
    if(h.Authorization!=='Bearer fake-token') return 'lost the Authorization header';
    return eq(h.ConsistencyLevel,'eventual');
  });
  await t('g() still works when no headers are given', async ()=>{
    const {calls}=await withFetch(()=>({ok:true, json:async()=>({value:[]})}), ()=>g('/x'));
    return eq(calls[0].headers.Authorization,'Bearer fake-token');
  });
  await t('g() still raises Graph errors with status and code', async ()=>{
    let threw=null;
    try{
      await withFetch(()=>({ok:false, status:403, statusText:'Forbidden',
        json:async()=>({error:{code:'Authorization_RequestDenied', message:'Insufficient privileges'}})}),
        ()=>g('/x',{ConsistencyLevel:'eventual'}));
    }catch(e){ threw=e; }
    if(!threw) return 'resolved on a 403';
    return threw.status===403 && threw.code==='Authorization_RequestDenied'
      ? true : `lost error detail: status=${threw.status} code=${threw.code}`;
  });

  /* ---- assignmentContext against a stubbed Graph ----
     The paging, the nextLink rewrite, the page bound and the principal matching
     are pure logic and were previously untested, because reaching them needed a
     live tenant. Swapping g() for a stub covers all of it here. What remains for
     a live run is only whether real Graph accepts the two queries, which the
     first case below pins so a "simplification" cannot silently change them.
     g() is a top-level function declaration, so it is a property of the global
     object and can be replaced. Always restore it in a finally. */
  const withGraph=async (handler, fn)=>{
    const realG=g;
    const calls=[];
    try{
      window.g=async path=>{ calls.push(path); return handler(path, calls.length); };
      const out=await fn();
      return {out, calls};
    } finally { window.g=realG; }
  };

  await t('assignmentContext queries both endpoints in the expected shape', async ()=>{
    const {out,calls}=await withGraph(
      path=>/appRoleAssignedTo/.test(path)
        ? {value:[{principalId:'g1'},{principalId:'u9'},{}]}
        : {value:[{id:'g1'},{id:'g2'},{}]},
      ()=>assignmentContext('sp1','user@example.org'));
    if(!calls.length) return 'the stub was never called, so g() could not be replaced';
    if(calls.length!==2) return `made ${calls.length} requests, expected 2`;
    if(!/^\/servicePrincipals\/sp1\/appRoleAssignedTo\?\$select=principalId&\$top=999$/.test(calls[0]))
      return `first query changed: ${calls[0]}`;
    if(!/^\/users\/user%40example\.org\/transitiveMemberOf\/microsoft\.graph\.group\?\$select=id&\$top=999$/.test(calls[1]))
      return `second query changed: ${calls[1]}`;
    /* The empty objects must be skipped rather than counted. */
    if(out.assigned.size!==2) return `collected ${out.assigned.size} principals, expected 2`;
    if(out.groupIds.join(',')!=='g1,g2') return `collected groups [${out.groupIds}]`;
    return out.complete===true&&out.truncated===false?true:`complete=${out.complete} truncated=${out.truncated}`;
  });

  await t('assignmentContext follows @odata.nextLink and strips the absolute prefix', async ()=>{
    const {out,calls}=await withGraph(
      path=>{
        if(!/appRoleAssignedTo|more/.test(path)) return {value:[{id:'g9'}]};
        return /more/.test(path)
          ? {value:[{principalId:'second-page'}]}
          : {value:[{principalId:'first-page'}],
             '@odata.nextLink':'https://graph.microsoft.com/v1.0/more?$skiptoken=abc'};
      },
      ()=>assignmentContext('sp1','u@x.org'));
    if(out.assigned.size!==2) return `collected ${out.assigned.size} across pages, expected 2`;
    if(/^https:\/\//.test(calls[1]||'')) return `nextLink not rewritten to a path: ${calls[1]}`;
    if(calls[1]!=='/more?$skiptoken=abc') return `unexpected second request: ${calls[1]}`;
    return out.complete===true?true:'marked incomplete despite finishing';
  });

  await t('assignmentContext stops at the page bound instead of looping forever', async ()=>{
    const {out,calls}=await withGraph(
      (path,n)=> /appRoleAssignedTo|more/.test(path)
        ? {value:[{principalId:'p'+n}], '@odata.nextLink':'https://graph.microsoft.com/v1.0/more?page='+n}
        : {value:[{id:'g1'}]},
      ()=>assignmentContext('sp1','u@x.org'));
    if(calls.length!==11) return `made ${calls.length} requests, expected 10 for the bounded endpoint plus 1`;
    if(out.truncated!==true) return 'did not set truncated';
    if(out.complete!==false) return 'claimed complete despite truncating';
    /* Incomplete data must never produce a failure verdict. That would recreate
       the exact false negative this whole mechanism exists to remove. */
    const v=analyseAssignments([],{id:'sp1',displayName:'T',appRoleAssignmentRequired:true},out);
    return v.st.assigned==='warn'?true:`verdict was ${v.st.assigned}, must not be fail on partial data`;
  });

  await t('a Graph failure propagates so the live run can fall back', async ()=>{
    let threw=null;
    try{
      await withGraph(()=>{ const e=new Error('Insufficient privileges'); e.status=403; throw e; },
        ()=>assignmentContext('sp1','u@x.org'));
    }catch(e){ threw=e; }
    if(!threw) return 'resolved instead of rejecting, so a 403 would look like "no groups"';
    return threw.status===403?true:`rejected with the wrong error: ${threw.message}`;
  });

  await t('a group-inherited assignment resolves end to end', async ()=>{
    const {out}=await withGraph(
      path=>/appRoleAssignedTo/.test(path)?{value:[{principalId:'group-A'}]}
                                          :{value:[{id:'group-A'},{id:'group-B'}]},
      ()=>assignmentContext('sp1','u@x.org'));
    out.userId='user-1';
    const v=analyseAssignments([],{id:'sp1',displayName:'T',appRoleAssignmentRequired:true},out);
    if(v.st.assigned!=='pass') return `verdict ${v.st.assigned}, expected pass`;
    return has(v.rows,/through 1 assigned group/);
  });

  await t('a user in no assigned group is still correctly failed', async ()=>{
    const {out}=await withGraph(
      path=>/appRoleAssignedTo/.test(path)?{value:[{principalId:'some-other-group'}]}
                                          :{value:[{id:'group-B'}]},
      ()=>assignmentContext('sp1','u@x.org'));
    out.userId='user-1';
    const v=analyseAssignments([],{id:'sp1',displayName:'T',appRoleAssignmentRequired:true},out);
    return v.st.assigned==='fail'?has(v.rows,/AADSTS50105/):`verdict ${v.st.assigned}, expected fail`;
  });

  await t('the real g() is restored after stubbing', ()=>eq(typeof g,'function')===true
    && !/calls\.push/.test(String(g)) ? true : 'g() is still the stub, later tests would be corrupted');

  /* ---- item 3: a missing status is not a success ---- */
  await t('real success is green',           ()=>has(analyseSignIns([{status:{errorCode:0}}]).rows,/<td class="st-pass">success<\/td>/));
  await t('real failure is red',             ()=>has(analyseSignIns([{status:{errorCode:50105}}]).rows,/<td class="st-fail">AADSTS50105<\/td>/));
  await t('missing status is not green',      ()=>not(analyseSignIns([{correlationId:'c'}]).rows,/st-pass/));
  await t('missing status warns the segment', ()=>eq(analyseSignIns([{correlationId:'c'}]).st.signin,'warn'));
  await t('a real failure outranks an unknown',()=>eq(analyseSignIns([{correlationId:'c'},{status:{errorCode:50105}}]).st.signin,'fail'));

  /* Report-only Conditional Access. These sign-ins succeed, so the old filter
     on result==='failure' rendered them as nothing, hiding the one signal that
     predicts an outage before it happens. */
  const ro=res=>[{status:{errorCode:0},correlationId:'c',conditionalAccessStatus:'reportOnly',
    appliedConditionalAccessPolicies:[{result:res,displayName:'Block legacy auth'}]}];
  await t('a report-only failure is surfaced, not filtered out', ()=>
    has(analyseSignIns(ro('reportOnlyFailure')).rows,/would have blocked/));
  await t('a report-only failure names the policy', ()=>
    has(analyseSignIns(ro('reportOnlyFailure')).rows,/Block legacy auth/));
  await t('a report-only failure warns the segment', ()=>
    eq(analyseSignIns(ro('reportOnlyFailure')).st.signin,'warn'));
  await t('a report-only failure does not fake a failed sign-in', ()=>{
    const r=analyseSignIns(ro('reportOnlyFailure'));
    return /st-fail/.test(r.rows) ? 'rendered the sign-in as failed when it succeeded' : has(r.rows,/st-pass/);
  });
  await t('a report-only failure adds a summary row', ()=>
    has(analyseSignIns(ro('reportOnlyFailure')).rows,/1 of the sign-ins above would have been blocked/));
  await t('a report-only interruption is surfaced separately', ()=>
    has(analyseSignIns(ro('reportOnlyInterrupted')).rows,/would have interrupted/));
  await t('a report-only success stays quiet', ()=>{
    const r=analyseSignIns(ro('reportOnlySuccess'));
    return /would have/.test(r.rows) ? 'warned about a policy that would have allowed it' : eq(r.st.signin,'pass');
  });
  await t('an enforced block still reads as blocked', ()=>{
    const r=analyseSignIns([{status:{errorCode:53003},correlationId:'c',conditionalAccessStatus:'failure',
      appliedConditionalAccessPolicies:[{result:'failure',displayName:'Require MFA'}]}]);
    if(!/blocked by Require MFA/.test(r.rows)) return 'lost the enforced block label';
    if(/would have/.test(r.rows)) return 'labelled an enforced block as report-only';
    return eq(r.st.signin,'fail');
  });
  await t('an enforced failure outranks a report-only warning', ()=>eq(
    analyseSignIns([...ro('reportOnlyFailure'),{status:{errorCode:53003}}]).st.signin,'fail'));

  /* The empty case names the likeliest cause when a user filter was applied.
     Paste mode passes no options, so it keeps the general wording. */
  await t('an empty log filtered by user says to clear the user field', ()=>{
    const r=analyseSignIns([],{filteredByUser:true});
    if(!/has not signed in to this app/.test(r.rows)) return 'did not name the likely cause';
    return has(r.rows,/Clear the <b>Affected user<\/b> field/);
  });
  await t('an empty log with no user filter keeps the general wording', ()=>{
    const r=analyseSignIns([]);
    if(/Affected user/.test(r.rows)) return 'suggested clearing a filter that was never applied';
    return has(r.rows,/the filter did not match/);
  });
  await t('both empty variants keep the Free tenant line', ()=>{
    const a=analyseSignIns([],{filteredByUser:true}).rows, b=analyseSignIns([]).rows;
    return /Free tenants cannot serve/.test(a)&&/Free tenants cannot serve/.test(b)
      ? true : 'lost the line districts on A1 need';
  });
  await t('the empty note stays short enough to read mid-call', ()=>{
    const text=analyseSignIns([],{filteredByUser:true}).rows.replace(/<[^>]+>/g,'');
    const sentences=(text.match(/\.\s|\.$/g)||[]).length;
    return sentences<=3 ? true : `grew to ${sentences} sentences, which gets skipped`;
  });
  await t('opts does not disturb a populated log', ()=>
    eq(analyseSignIns([{status:{errorCode:0}}],{filteredByUser:true}).st.signin,'pass'));

  /* ---- identity masking ----
     Live tenant output names district staff and students and these sessions get
     screenshared, so it is masked by default. The domain survives because it is
     diagnostic rather than personal. This is a screenshare aid, not a security
     control: both forms are in the DOM and CSS picks one. */
  await t('maskId keeps the first character and the domain', ()=>eq(maskId('jdoe@district.k12.st.us'),'j•••@district.k12.st.us'));
  await t('maskId handles a value with no domain', ()=>eq(maskId('someuser'),'s•••'));
  await t('maskId handles null and empty without throwing', ()=>eq(maskId(null)+maskId(''),''));
  await t('pii emits both a masked and a full form', ()=>{
    const h=pii('jdoe@district.k12.st.us');
    if(!/<i>j•••@district\.k12\.st\.us<\/i>/.test(h)) return 'no masked form';
    return has(h,/<b>jdoe@district\.k12\.st\.us<\/b>/);
  });
  await t('pii escapes a hostile identity in both forms', ()=>{
    const evil='<img src=x>@e.com';
    const h=pii(evil);
    return h.includes(evil) ? 'inserted the hostile string verbatim' : has(h,/&lt;img/);
  });
  await t('masking is on by default', ()=>
    document.body.classList.contains('revealed') ? 'page started revealed' : true);
  await t('the user card masks UPN, mail and display name', ()=>{
    const r=analyseUser({userPrincipalName:'jdoe@d.org',mail:'j.doe@d.org',displayName:'Jane Doe',
      proxyAddresses:['smtp:alias@d.org']});
    for(const [label,re] of [['UPN',/j•••@d\.org/],['mail',/j•••@d\.org/],
                             ['display name',/J•••/],['proxy address',/s•••:?/]])
      if(!re.test(r.rows)) return `${label} not masked`;
    return has(r.rows,/class="pii"/);
  });
  await t('the sign-in table masks the UPN', ()=>
    has(analyseSignIns([{status:{errorCode:0},userPrincipalName:'jdoe@d.org'}]).rows,/j•••@d\.org/));
  await t('an empty UPN does not render a stray mask', ()=>
    not(analyseSignIns([{status:{errorCode:0}}]).rows,/•••/));
  await t('the reveal toggle flips the class and the label', ()=>{
    const b=$('revealPii'), before=document.body.classList.contains('revealed');
    try{
      b.click();
      if(!document.body.classList.contains('revealed')) return 'class not applied';
      if(b.getAttribute('aria-pressed')!=='true') return 'aria-pressed not updated';
      if(!/Hide/.test(b.textContent)) return `label still reads ${b.textContent}`;
      b.click();
      return document.body.classList.contains('revealed') ? 'did not toggle back' : eq(b.getAttribute('aria-pressed'),'false');
    } finally { document.body.classList.toggle('revealed', before); }
  });
  /* The boundary is deliberate: you pasted these yourself and reading the claim
     values is the entire point of those tabs. */
  await t('the JWT tab is deliberately not masked', ()=>{
    $('jwtIn').value=[btoa(JSON.stringify({alg:'RS256'})),
      btoa(JSON.stringify({iss:'https://sts.windows.net/x/',upn:'jdoe@d.org',email:'jdoe@d.org'})),'s']
      .map(x=>x.replace(/=+$/,'')).join('.');
    inspectJwt();
    const h=$('jwtOut').innerHTML;
    $('jwtIn').value=''; $('jwtOut').innerHTML='';
    return h.includes('jdoe@d.org') ? true : 'the OIDC tab masked a claim value, which defeats its purpose';
  });

  /* ---- Refresh sign-ins ---- */
  await t('signInQuery pins the filter shape', ()=>{
    const q=signInQuery('app-guid','jdoe@d.org');
    if(!/^\/auditLogs\/signIns\?\$filter=/.test(q)) return q;
    if(!/%24top=15|\$top=15/.test(q)) return `lost $top: ${q}`;
    return has(q,/userPrincipalName%20eq/);
  });
  await t('signInQuery omits the user clause when no user is given', ()=>
    not(signInQuery('app-guid',''),/userPrincipalName/));
  await t('signInQuery escapes an apostrophe in the UPN', ()=>
    has(signInQuery('app-guid',"o'brien@d.org"),/o''brien/));
  await t('Refresh sign-ins starts disabled', ()=>eq($('refreshLogs').disabled,true));

  /* ---- item 4: a truncated paste must not abort the inspector ---- */
  const utc=s=>Array.from(s,c=>c.charCodeAt(0));
  await t('certValidity reads a well-formed UTCTime pair', ()=>{
    const v=certValidity(new Uint8Array([0x30,0x1E,0x17,0x0D,...utc('260812000000Z'),0x17,0x0D,...utc('290812000000Z'),...Array(33).fill(0)]));
    if(!v) return 'returned null for a valid pair';
    return v.from.toISOString().slice(0,10)==='2026-08-12'&&v.to.toISOString().slice(0,10)==='2029-08-12'
      ? true : `read ${v.from.toISOString()} to ${v.to.toISOString()}`;
  });
  await t('certValidity never returns an Invalid Date', ()=>eq(
    certValidity(new Uint8Array([0x30,0x1E,0x17,0x0D,...Array(13).fill(0x41),0x17,0x0D,...Array(13).fill(0x41),...Array(33).fill(0)])),null));

  const samlFixture=cert=>`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Destination="https://sp.example/acs" IssueInstant="2026-08-12T00:00:00Z">
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
<saml:Assertion><saml:Issuer>https://sts.windows.net/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/</saml:Issuer>
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
<saml:Subject><saml:NameID>jdoe@example.org</saml:NameID></saml:Subject>
<saml:Conditions NotBefore="2026-08-12T00:00:00Z" NotOnOrAfter="2026-08-12T01:00:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example</saml:Audience></saml:AudienceRestriction></saml:Conditions>
</saml:Assertion></samlp:Response>`;
  const inspect=async cert=>{
    $('samlIn').value=samlFixture(cert);
    $('samlOut').innerHTML='SENTINEL';
    await inspectSaml();
    return $('samlOut').innerHTML;
  };
  await t('truncated certificate still renders a verdict', async ()=>{
    const h=await inspect('!!! not base64 !!!');
    if(h==='SENTINEL') return 'panel left stale, user would read the previous assertion as current';
    if(!/not decodable/.test(h)) return 'rendered but did not explain the bad certificate';
    return has(h,/Audience/);
  });
  await t('truncated certificate does not also claim "not embedded"', async ()=>not(await inspect('!!! not base64 !!!'),/not embedded/));
  await t('non-DER certificate bytes still render',   async ()=>not(await inspect(btoa('not a DER certificate')),/SENTINEL/));
  await t('bogus date bytes still render',            async ()=>not(await inspect(btoa(String.fromCharCode.apply(null,[0x30,0x1E,0x17,0x0D,...Array(13).fill(0x41),0x17,0x0D,...Array(13).fill(0x41),...Array(33).fill(0)]))),/SENTINEL/));

  /* ---- decoders ---- */
  await t('decodeSaml detects raw XML',      ()=>eq(decodeSaml('<samlp:Response/>').how,'raw XML'));
  await t('decodeSaml detects plain base64', ()=>has(decodeSaml(btoa('<samlp:Response/>')).how,/POST binding/));
  await t('decodeSaml rejects empty input',  ()=>{ try{ decodeSaml('   '); return 'accepted empty input'; }catch(e){ return true; } });
  await t('decodeSaml detects deflated base64', ()=>{
    if(!window.pako) return 'skip: pako did not load, check the CDN script tag';
    const z=pako.deflateRaw(new TextEncoder().encode('<samlp:AuthnRequest/>'));
    let s=''; z.forEach(b=>s+=String.fromCharCode(b));
    return has(decodeSaml(btoa(s)).how,/Redirect binding/);
  });
  const mkJwt=(h,b)=>[btoa(JSON.stringify(h)),btoa(JSON.stringify(b)),'sig'].map(x=>x.replace(/=+$/,'')).join('.');
  await t('parseJwt rejects a two-segment token', ()=>{ try{ parseJwt('a.b'); return 'accepted it'; }catch(e){ return has(e.message,/three/); } });
  await t('parseJwt reads the body',              ()=>eq(parseJwt(mkJwt({alg:'RS256'},{oid:'x'})).body.oid,'x'));
  await t('parseJwt tolerates a Bearer prefix',   ()=>eq(parseJwt('Bearer '+mkJwt({alg:'RS256'},{oid:'y'})).body.oid,'y'));

  /* Anything with two dots gets past the segment count, so the messages beyond
     it are what a mis-paste actually meets. They used to be raw atob and
     JSON.parse output, unreadable and naming nothing. */
  const why=v=>{ try{ parseJwt(v); return null; }catch(e){ return e.message; } };
  await t('a three-part non-token names the segment and mentions JWT', ()=>{
    const m=why('not.a.token');
    if(!m) return 'accepted a non-token';
    if(/is not valid JSON|Unexpected token/.test(m)) return `raw parser message leaked: ${m}`;
    if(!/header|payload/.test(m)) return `does not name the segment: ${m}`;
    return has(m,/JWT/);
  });
  await t('valid base64 that is not JSON is explained', ()=>{
    const m=why(btoa('hello')+'.'+btoa('world')+'.sig');
    return /not JSON/.test(m||'') ? true : `unclear message: ${m}`;
  });
  /* Header first, then payload, so an empty payload needs a valid header ahead
     of it to be reached at all. 'e30' is base64 for {}. */
  await t('an empty segment is called out as empty', ()=>{
    const m=why('e30..sig');
    if(!/empty/.test(m||'')) return `unclear message: ${m}`;
    return has(m,/payload/);
  });
  await t('a bad header is reported before the payload is looked at', ()=>
    has(why('!!!.e30.sig')||'', /header/));
  await t('no decoder message contains a replacement character', ()=>{
    const bad=['not.a.token','a..c',btoa('x')+'.'+btoa('y')+'.z','!!!.!!!.!!!']
      .map(why).filter(Boolean).filter(m=>/�/.test(m));
    return bad.length ? `mojibake in: ${bad[0]}` : true;
  });
  await t('the decoder error reaches the panel, not the console', ()=>{
    $('jwtIn').value='not.a.token'; $('jwtOut').innerHTML='';
    inspectJwt();
    const h=$('jwtOut').innerHTML;
    $('jwtIn').value=''; $('jwtOut').innerHTML='';
    if(!/Could not decode/.test(h)) return 'no error card rendered';
    if(!/header segment/.test(h)) return 'card did not name the segment';
    return has(h,/JWT/);
  });
  await t('a Graph audience is called out',       ()=>{ $('jwtIn').value=mkJwt({alg:'RS256'},{iss:'https://sts.windows.net/x/',aud:'https://graph.microsoft.com'}); inspectJwt(); return has($('jwtOut').innerHTML,/not an identity token/); });

  /* ---- item 5: the OData filter must survive a hostile app name ---- */
  await t('app name with & does not inject a query parameter', ()=>{
    const q=spQuery("Acme & Sons", 'id');
    if(/&\$select/.test(q.replace(/%26/g,''))===false) return `lost the $select: ${q}`;
    return not(q.split('$filter=')[1].split('&')[0], /&/);
  });
  await t('app name with # does not truncate the URL', ()=>not(spQuery('Sharp#Name','id'),/#/));
  /* encodeURIComponent leaves ' and ( ) alone, which is legal in a query
     string. What matters is that OData sees a doubled quote. */
  await t('app name with an apostrophe is OData-escaped', ()=>has(spQuery("O'Brien School",'id'),/'O''Brien%20School'/));
  await t('a + in an app name is encoded, not read as a space', ()=>has(spQuery('A+B','id'),/%2B/));
  await t('GUID app id uses the appId filter and no $top', ()=>{
    const q=spQuery('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','id');
    return /appId%20eq/.test(q)&&!/\$top/.test(q) ? true : q;
  });
  await t('a plain name still uses startswith and $top', ()=>{
    const q=spQuery('Test App','id');
    return /startswith\(displayName/.test(q)&&/\$top=10/.test(q) ? true : q;
  });

  /* ---- item 6: MSAL failing to start must disable sign-in, not stay silent ---- */
  await t('MSAL init failure disables sign-in and says why', async ()=>{
    const realMsal=window.msal, cid=$('cfgClient').value, tid=$('cfgTenant').value;
    try{
      window.msal={PublicClientApplication:function(){ throw new Error('simulated init failure'); }};
      $('cfgClient').value='11111111-2222-3333-4444-555555555555';
      await buildAuth();
      if(!$('signIn').disabled) return 'sign-in button left enabled';
      if(!/could not start/.test($('who').innerHTML)) return `no explanation: ${$('who').textContent.slice(0,80)}`;
      if(msalApp!==null) return 'left a half-built msalApp in place';
      return true;
    } finally {
      window.msal=realMsal; $('cfgClient').value=cid; $('cfgTenant').value=tid;
      await buildAuth();
    }
  });

  /* ---- item 7: the popup must be opened inside the click, not after an await ---- */
  await t('Graph Explorer popup opens synchronously with the click', ()=>{
    const realOpen=window.open;
    let openedSynchronously=false;
    try{
      window.open=()=>{ openedSynchronously=true; return null; };
      document.querySelector('[data-ge]').click();
      /* Checked immediately: nothing has awaited yet, so a deferred open fails. */
      return openedSynchronously ? true : 'window.open was not called during the click';
    } finally { window.open=realOpen; }
  });
  await t('a blocked popup is reported and the query is shown', async ()=>{
    const realOpen=window.open;
    try{
      window.open=()=>null;
      document.querySelector('[data-ge]').click();
      await new Promise(r=>setTimeout(r,50));
      if(!/popup was blocked/.test($('geNote').innerHTML)) return `note did not mention the block: ${$('geNote').textContent.slice(0,80)}`;
      return has($('liveOut').innerHTML,/Query to run in Graph Explorer/);
    } finally { window.open=realOpen; clearPasted(); }
  });

  /* ---- item 10: clearing must drop the in-memory service principal ---- */
  await t('Clear drops the pasted service principal', ()=>{
    $('pasteIn').value=JSON.stringify({'@odata.context':'x/$metadata#servicePrincipals',value:[spCert(300)]});
    $('pasteGo').click();
    if(!pastedSp) return 'paste did not record a service principal to begin with';
    clearPasted();
    return eq(pastedSp,null);
  });
  await t('Clear empties the paste box and the output', ()=>{
    $('pasteIn').value='{"hello":"world"}'; $('pasteGo').click(); clearPasted();
    return eq($('pasteIn').value+$('liveOut').innerHTML,'');
  });

  /* ---- item 13: encryption certificates are not signing certificates ---- */
  await t('a token-encryption certificate is not listed as signing', ()=>{
    const sp={displayName:'T',appId:'a',id:'sp1',preferredTokenSigningKeyThumbprint:hex,
      keyCredentials:[{usage:'Encrypt',type:'AsymmetricX509Cert',customKeyIdentifier:b64,
        endDateTime:new Date(Date.now()+86400000).toISOString()}]};
    const r=analyseServicePrincipal(sp);
    return has(r.certRows,/none returned/);
  });
  await t('a signing certificate without a usage field is still listed', ()=>{
    const sp={displayName:'T',appId:'a',id:'sp1',preferredTokenSigningKeyThumbprint:hex,
      keyCredentials:[{type:'AsymmetricX509Cert',customKeyIdentifier:b64,
        endDateTime:new Date(Date.now()+300*86400000).toISOString()}]};
    return has(analyseServicePrincipal(sp).certRows,/Active certificate/);
  });

  /* ---- documented scope invariants ----
     Verified against a live token on 2026-08-12: the granted list came back as
     Application.Read.All, AuditLog.Read.All, Directory.Read.All, User.Read.All,
     openid, profile, email. MSAL adds openid and profile to every request on its
     own. No offline_access, so no refresh token, so the Setup tab is telling
     district admins the truth. That claim is made while asking for directory
     access, so it has to stay true. These pin the code side of it. */
  await t('SCOPES does not request offline_access', ()=>not(SCOPES.join(' '),/offline_access/));
  await t('SCOPES is exactly the four documented delegated permissions', ()=>{
    const want=['Application.Read.All','AuditLog.Read.All','Directory.Read.All','User.Read.All'];
    return SCOPES.slice().sort().join(',')===want.sort().join(',') ? true
      : `SCOPES is now [${SCOPES}]. Adding one widens what a district admin must consent to, so change CLAUDE.md invariant 6 deliberately rather than editing this test.`;
  });
  await t('every requested scope is read-only', ()=>{
    const bad=SCOPES.filter(s=>!/\.Read(\.All)?$/.test(s));
    return bad.length?`not read-only: ${bad.join(', ')}`:true;
  });

  /* The Setup tab is what a district administrator reads before consenting, so
     it has to describe what the code actually asks for. Documentation drifting
     away from SCOPES is a promise quietly becoming untrue, and nothing else
     would catch it. */
  const permRows=()=>Array.from(document.querySelectorAll('#p-setup table.claims tbody tr'))
    .map(tr=>Array.from(tr.children).map(td=>td.textContent.trim()));
  await t('Setup carries exactly one permissions table', ()=>
    eq(document.querySelectorAll('#p-setup table.claims').length,1));
  await t('the Setup permissions table matches SCOPES', ()=>{
    const rows=permRows();
    if(rows.length<SCOPES.length) return `only ${rows.length} rows, so the table has moved or lost entries`;
    const required=rows.filter(c=>c[1]==='required').map(c=>c[0]).sort().join(', ');
    const scopes=SCOPES.slice().sort().join(', ');
    return required===scopes ? true
      : `the table says [${required}] but the code requests [${scopes}]`;
  });
  await t('anything the table calls optional is genuinely not requested', ()=>{
    const lying=permRows().filter(c=>c[1]==='optional').map(c=>c[0]).filter(s=>SCOPES.includes(s));
    return lying.length?`marked optional but requested anyway: ${lying.join(', ')}`:true;
  });

  /* ---- item 8: supply chain ----
     Scoped to third-party origins. SRI and version pinning are about code
     arriving from someone else's server; a same-origin file such as this one
     needs neither, and including it produced a false failure. */
  const thirdParty=()=>Array.from(document.querySelectorAll('script[src]')).filter(s=>{
    const u=s.getAttribute('src')||'';
    return /^https?:\/\//i.test(u) && new URL(u).origin!==location.origin;
  });
  await t('there is at least one third-party script to check', ()=>{
    return thirdParty().length>=2 ? true : `found ${thirdParty().length}, so the two checks below prove nothing`;
  });
  await t('every third-party script carries an integrity hash and crossorigin', ()=>{
    const bad=thirdParty()
      .filter(s=>!s.getAttribute('integrity')||!s.getAttribute('crossorigin'))
      .map(s=>s.getAttribute('src'));
    return bad.length?`unprotected: ${bad.join(', ')}`:true;
  });
  await t('no third-party script uses a floating version range', ()=>{
    const bad=thirdParty()
      .filter(s=>!/\d+\.\d+\.\d+/.test(s.getAttribute('src')))
      .map(s=>s.getAttribute('src'));
    return bad.length?`floating: ${bad.join(', ')}`:true;
  });
  await t('both third-party libraries actually loaded under SRI', ()=>{
    const missing=[];
    if(typeof pako==='undefined') missing.push('pako');
    if(typeof msal==='undefined') missing.push('msal');
    return missing.length?`did not load, so a hash may be stale: ${missing.join(', ')}`:true;
  });

  /* ---- item 9: CSP ---- */
  await t('a CSP is declared and locks down where data can go', ()=>{
    const m=document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if(!m) return 'no CSP meta tag';
    const c=m.getAttribute('content')||'';
    if(!/default-src 'none'/.test(c)) return 'default-src is not none';
    if(/connect-src[^;]*[* ]\*/.test(c)) return 'connect-src allows a wildcard';
    if(!/connect-src[^;]*graph\.microsoft\.com/.test(c)) return 'connect-src omits Graph';
    if(!/connect-src[^;]*login\.microsoftonline\.com/.test(c)) return 'connect-src omits the login endpoint';
    return has(c,/frame-src[^;]*login\.microsoftonline\.com/);
  });

  /* ---- item 11: nothing from a tenant may reach the DOM unescaped ---- */
  await t('esc covers all six characters', ()=>eq(esc('&<>"\'`'),'&amp;&lt;&gt;&quot;&#39;&#96;'));
  await t('a hostile display name cannot inject markup', ()=>{
    const evil='<img src=x onerror="alert(1)">';
    const r=analyseServicePrincipal({displayName:evil,appId:evil,id:evil,loginUrl:evil,
      servicePrincipalNames:[evil],replyUrls:[evil],notificationEmailAddresses:[evil]});
    const all=r.rows+r.certRows;
    if(all.includes(evil)) return 'inserted the hostile string verbatim';
    return has(all,/&lt;img/);
  });
  await t('a hostile user object cannot inject markup', ()=>{
    /* The slash is escaped so this string cannot close the enclosing script
       element. Writing it raw truncates the whole page's JavaScript. */
    const evil='<script>x<\/script>';
    const r=analyseUser({userPrincipalName:evil,mail:evil,displayName:evil,proxyAddresses:[evil],
      onPremisesSyncEnabled:true,onPremisesImmutableId:evil,onPremisesSamAccountName:evil});
    if(r.rows.includes(evil)) return 'inserted the hostile string verbatim';
    return has(r.rows,/&lt;script/);
  });
  await t('a hostile sign-in log entry cannot inject markup', ()=>{
    const evil='<b onclick="x">';
    const r=analyseSignIns([{status:{errorCode:1,failureReason:evil},userPrincipalName:evil,
      correlationId:evil,createdDateTime:evil,conditionalAccessStatus:evil,
      appliedConditionalAccessPolicies:[{result:'failure',displayName:evil}]}]);
    if(r.rows.includes(evil)) return 'inserted the hostile string verbatim';
    return has(r.rows,/&lt;b/);
  });
  await t('a hostile assignment group id cannot inject markup', ()=>{
    const evil='<i>x</i>';
    const r=analyseAssignments([],{id:'sp1',displayName:'T',appRoleAssignmentRequired:true},
      {userId:'u1',groupIds:[evil],assigned:new Set([evil]),complete:true,truncated:false});
    return r.rows.includes(evil)?'inserted the hostile string verbatim':has(r.rows,/&lt;i&gt;/);
  });

  /* ---- item 12: PowerShell PascalCase ---- */
  await t('camelKeys normalises PascalCase', ()=>eq(camelKeys({DisplayName:'x'}).displayName,'x'));
  await t('camelKeys leaves camelCase and @odata keys alone', ()=>{
    const n=camelKeys({'@odata.context':'c',appId:'a',nested:{userPrincipalName:'u'}});
    return n['@odata.context']==='c'&&n.appId==='a'&&n.nested.userPrincipalName==='u'?true:JSON.stringify(n);
  });
  await t('camelKeys prefers a genuine camelCase key', ()=>eq(camelKeys({Id:'pascal',id:'camel'}).id,'camel'));
  await t('camelKeys recurses through arrays', ()=>eq(camelKeys({V:[{AppId:'a'}]}).v[0].appId,'a'));
  await t('a PowerShell service principal analyses correctly end to end', ()=>{
    const ps={DisplayName:'Test App',AppId:'a',Id:'sp1',PreferredSingleSignOnMode:'saml',
      AppRoleAssignmentRequired:true,PreferredTokenSigningKeyThumbprint:hex,
      KeyCredentials:[{Usage:'Verify',Type:'AsymmetricX509Cert',CustomKeyIdentifier:bytes,
        EndDateTime:new Date(Date.now()-30*86400000).toISOString()}]};
    const r=analyseServicePrincipal(camelKeys(ps));
    if(r.st.sso!=='pass') return `sso read as ${r.st.sso}`;
    /* PascalCase keys plus a byte-array thumbprint plus an expired cert. */
    return eq(r.st.cert,'fail');
  });
  await t('paste mode recognises PowerShell output', ()=>{
    $('pasteIn').value=JSON.stringify({DisplayName:'Test App',AppId:'a',Id:'sp1',
      PreferredSingleSignOnMode:'saml',ServicePrincipalNames:['https://x'],KeyCredentials:[]});
    $('pasteGo').click();
    const okNow=/Application configuration/.test($('liveOut').innerHTML);
    clearPasted();
    return okNow?true:'shape not recognised';
  });

  /* ---- item 14: the flat fallbacks must match the color-mix values ---- */
  await t('flat colour fallbacks match their color-mix equivalents', ()=>{
    const probe=document.createElement('div'); document.body.appendChild(probe);
    /* A hex resolves to rgb(), but color-mix resolves to color(srgb 0.086 ...),
       so both forms have to be parsed. Scraping digits reads the decimals as
       integers and produces nonsense. */
    const read=v=>{
      probe.style.background=''; probe.style.background=v;
      const s=getComputedStyle(probe).backgroundColor;
      let m=s.match(/^rgba?\(([^)]+)\)/);
      if(m) return m[1].split(/[\s,\/]+/).filter(Boolean).slice(0,3).map(Number);
      m=s.match(/^color\(srgb\s+([^)]+)\)/);
      if(m) return m[1].trim().split(/[\s\/]+/).filter(Boolean).slice(0,3).map(x=>Math.round(parseFloat(x)*255));
      return [];
    };
    const pairs=[
      ['color-mix(in srgb, #141820, #3b82f6 5%)','#161d2b','--card'],
      ['color-mix(in srgb, #161d2b, #3b82f6 14%)','#1b2b47','--accent-soft'],
      ['color-mix(in srgb, #161d2b, #3b82f6 40%)','#25457c','--accent-line'],
      ['color-mix(in srgb, #3b82f6 18%, #161d2b)','#1d2f50','sidebar top'],
      ['color-mix(in srgb, #14b8a6 21%, #161d2b)','#163e45','sidebar bottom'],
    ];
    const bad=[];
    pairs.forEach(([mix,flat,name])=>{
      const a=read(mix), b=read(flat);
      if(a.length<3||b.length<3){ bad.push(`${name}: did not resolve`); return; }
      const d=Math.max(...a.map((x,i)=>Math.abs(x-b[i])));
      if(d>3) bad.push(`${name}: fallback ${flat} is ${d} off (${a} vs ${b})`);
    });
    probe.remove();
    return bad.length?bad.join('; '):true;
  });
  await t('the card token resolves to a paintable colour', ()=>{
    const probe=document.createElement('div');
    probe.style.background='var(--card)'; document.body.appendChild(probe);
    const bg=getComputedStyle(probe).backgroundColor; probe.remove();
    return bg&&bg!=='rgba(0, 0, 0, 0)'&&bg!=='transparent'?true:`resolved to ${bg}`;
  });

  /* ---- item 15: oversized input ---- */
  await t('an oversized paste is refused, not rendered', ()=>{
    $('pasteIn').value='x'.repeat(MAX_INPUT+1);
    $('pasteGo').click();
    const okNow=/Input too large/.test($('liveOut').innerHTML);
    clearPasted();
    return okNow?true:'accepted an oversized paste';
  });
  await t('an oversized SAML message is refused', async ()=>{
    $('samlIn').value='x'.repeat(MAX_INPUT+1);
    await inspectSaml();
    const okNow=/Input too large/.test($('samlOut').innerHTML);
    $('samlIn').value=''; $('samlOut').innerHTML='';
    return okNow?true:'accepted an oversized assertion';
  });
  await t('an oversized token is refused', ()=>{
    $('jwtIn').value='x'.repeat(MAX_INPUT+1);
    inspectJwt();
    const okNow=/Input too large/.test($('jwtOut').innerHTML);
    $('jwtIn').value=''; $('jwtOut').innerHTML='';
    return okNow?true:'accepted an oversized token';
  });
  await t('normal-sized input is not refused', ()=>{
    $('pasteIn').value=JSON.stringify({hello:'world'});
    $('pasteGo').click();
    const refused=/Input too large/.test($('liveOut').innerHTML);
    clearPasted();
    return refused?'refused a tiny paste':true;
  });

  /* ---- shape detection, both modes share this engine ---- */
  await t('paste mode recognises a service principal', ()=>{
    $('pasteIn').value=JSON.stringify({'@odata.context':'x/$metadata#servicePrincipals',value:[spCert(300)]});
    $('pasteGo').click();
    return has($('liveOut').innerHTML,/Application configuration/);
  });
  await t('paste mode rejects an unrecognised shape', ()=>{
    $('pasteIn').value=JSON.stringify({hello:'world'});
    $('pasteGo').click();
    return has($('liveOut').innerHTML,/Shape not recognised/);
  });
  await t('paste mode reports bad JSON instead of throwing', ()=>{
    $('pasteIn').value='{not json';
    $('pasteGo').click();
    return has($('liveOut').innerHTML,/Could not parse/);
  });

  /* Leave no fixture behind, in the inputs or in memory. clearPasted() also
     drops liveOut, which the results table below then fills. */
  clearPasted();
  ['samlIn','jwtIn'].forEach(id=>{ $(id).value=''; });
  ['samlOut','jwtOut'].forEach(id=>{ $(id).innerHTML=''; });

  const cls={pass:'st-pass',fail:'st-fail',skip:''};
  const table='<div style="overflow-x:auto"><table class="claims"><thead><tr><th>Result</th><th>Check</th><th>Detail</th></tr></thead><tbody>'+
    results.map(([s,n,d])=>`<tr><td class="${cls[s]}">${s.toUpperCase()}</td><td>${esc(n)}</td><td>${esc(d)}</td></tr>`).join('')+
    '</tbody></table></div>';
  const heading = fails
    ? `Self test: ${fails} of ${results.length} FAILED`
    : `Self test: ${results.length-skips} passed${skips?`, ${skips} skipped`:''}`;
  $('pageTitle').textContent='Self test';
  document.title=(fails?`${fails} FAILED`:'self test OK')+' | Federation Bench';
  $('liveOut').innerHTML=strip([{tag:'test',state:fails?'fail':skips?'warn':'pass'}],
    fails?'Do not deploy until these pass.':'All checks passed.')+card(heading,table);
  animateStrip();
  console[fails?'error':'log'](`self test: ${results.length-fails-skips} passed, ${fails} failed, ${skips} skipped`);
  return {passed:results.length-fails-skips, failed:fails, skipped:skips, results};
}
selfTest();
