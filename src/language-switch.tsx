/**
 * [INPUT]: 共享界面语言状态与可选的 Tauri 持久化命令。
 * [OUTPUT]: 侧栏底部的中文 / EN 切换；浏览器预览只改本地界面语言，桌面端成功持久化后再刷新。
 * [POS]: 唯一语言写入入口；桌面偏好由宿主持久化，预览不声称持久化。
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
import {useEffect,useState} from 'react';
import {invoke,isTauri} from '@tauri-apps/api/core';
import {useI18n,setLocale,type Locale} from './i18n';
export function LanguageSwitch(){
  const {locale,t}=useI18n();
  const nativeBridge=isTauri();
  const [busy,setBusy]=useState(nativeBridge),[error,setError]=useState('');
  useEffect(()=>{if(!nativeBridge)return;let live=true;void invoke<Locale>('ui_language_read').then(next=>{if(live)setLocale(next);}).catch(e=>{if(live)setError(String(e));}).finally(()=>{if(live)setBusy(false);});return()=>{live=false;};},[nativeBridge]);
  async function change(next:Locale){if(busy||next===locale)return;setError('');if(!nativeBridge){setLocale(next);return;}setBusy(true);try{await invoke('ui_language_write',{language:next});setLocale(next);}catch(e){setError(String(e));}finally{setBusy(false);}}
  return <><div className="language-switch" role="group" aria-label={t('界面语言')}>{(['zh','en'] as const).map(value=><button key={value} type="button" aria-pressed={value===locale} disabled={busy} onClick={()=>void change(value)}>{value==='zh'?'中文':'EN'}</button>)}</div>{error&&<p className="system-feedback error" role="alert">{t(error)}</p>}</>;
}
