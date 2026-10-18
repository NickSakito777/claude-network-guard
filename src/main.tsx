/**
 * [INPUT]: Guard 品牌、Laper Landing 壳、Cromma UI、共享 YAML、Guard/身份/浏览器/系统页面、快捷操作与网络入口。
 * [OUTPUT]: Guard 首页及原有功能页侧栏；版本信息与界面语言固定底部，不自动检查更新。
 * [POS]: 单窗口编排层；既有本机任务期间锁定导航，Guard 状态不从日志推断。
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
import { Panel, NavButton, MotionRoot, TooltipProvider } from 'cromma-ui';
import { ShieldCheck as GuardIcon, HomeDefault as HomeIcon, WindowBrowser as BrowserIcon, Settings01 as SettingsIcon, Share01 as NetworkIcon, FolderDefault as HelpIcon } from 'cromma-ui/pika';
import { Fragment, useEffect, useState } from 'react';
import {useI18n} from "./i18n";
import { createRoot } from 'react-dom/client';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { isTauri } from '@tauri-apps/api/core';
import { getVersion } from '@tauri-apps/api/app';
import { GuardHome } from './guard-home';
import { IdentityPanel } from './identities';
import { BrowserPanel } from './browser';
import { SystemPanel } from './system';
import { useQuickActions } from './quick-actions';
import { VpsPanel } from './vps';
import { LanguageSwitch } from './language-switch';
import { HelpPanel } from './help';
import './index.css';
import './style.css';
type Page = 'guard' | 'quick' | 'cleaner' | 'browser' | 'system' | 'vps' | 'help';
const titles: Record<Page, string> = { guard: '保护中心', quick: '傻瓜设置', cleaner: 'Claude 身份管理', browser: '浏览器环境', system: '电脑环境', vps: '网络环境', help: '使用说明' };
const icons: Record<Page, typeof HomeIcon> = { guard: GuardIcon, quick: HomeIcon, cleaner: GuardIcon, browser: BrowserIcon, system: SettingsIcon, vps: NetworkIcon, help: HelpIcon };

function VersionInfo() {
  const {t}=useI18n();
  const nativeBridge=isTauri();
  const [version,setVersion]=useState<string|null>(null),[error,setError]=useState('');
  useEffect(()=>{if(!nativeBridge)return;let live=true;void getVersion().then(value=>{if(live)setVersion(value);}).catch(cause=>{if(live)setError(String(cause));});return()=>{live=false;};},[nativeBridge]);
  return <small className="app-version">{!nativeBridge ? t('静态预览') : version ? `v${version}` : error ? t('版本信息读取失败：{error}',{error}) : t('读取版本信息…')}</small>;
}

function App() {
    const {t}=useI18n();
    const [emptyRequested,setEmptyRequested]=useState(false);
    const [page, setPage] = useState<Page>('guard'), [revision, setRevision] = useState(0), [advancedBusy, setAdvancedBusy] = useState(false);
    const quick = useQuickActions(() => setPage('quick'), () => setRevision(v => v + 1),()=>{setEmptyRequested(true);setRevision(v=>v+1);setPage("cleaner");});
    const locked = quick.busy || advancedBusy;
    return <><div className="drag-strip" onMouseDown={e => { if (e.button === 0 && isTauri())
        void getCurrentWindow().startDragging(); }}/><div className="app-shell"><aside className="app-sidebar">
    <div className="app-brand"><span className="app-brand-mark"><GuardIcon size={25} aria-hidden="true"/></span><strong>Guard</strong></div>
    <nav aria-label={t("主要页面")}>{(['guard', 'quick', 'vps', 'cleaner', 'browser', 'system', 'help'] as const).map(p => { const Icon = icons[p]; return <Fragment key={p}>{(p==='vps'||p==='help')&&<hr className="nav-divider"/>}<NavButton className="workspace-nav" active={page === p} aria-current={page === p ? "page" : undefined} disabled={locked} icon={<Icon size={18} aria-hidden="true"/>} onClick={() => {setEmptyRequested(false);setPage(p);}}>{t(titles[p])}</NavButton></Fragment>; })}</nav>
    <div className="sidebar-bottom"><VersionInfo/><LanguageSwitch /></div>
  </aside><Panel frame className="workspace">{page === 'guard' && <div className="cleaner-slot"><GuardHome/></div>}<fieldset disabled={advancedBusy} className={`cleaner-slot quick-fieldset ${page !== 'quick' ? 'page-hidden' : ''}`}>{quick.content}</fieldset>
    {page === 'cleaner' && <div className="cleaner-slot"><IdentityPanel key={revision} initialEmpty={emptyRequested} onBusy={setAdvancedBusy}/></div>}{page === 'browser' && <div className="cleaner-slot"><BrowserPanel key={revision} onBusy={setAdvancedBusy}/></div>}{page === 'system' && <div className="cleaner-slot"><SystemPanel key={revision} onBusy={setAdvancedBusy}/></div>}{page === 'vps' && <div className="cleaner-slot"><VpsPanel/></div>}{page === 'help' && <div className="cleaner-slot"><HelpPanel/></div>}
  </Panel></div></>;
}
document.title='Guard';
createRoot(document.getElementById('app')!).render(<MotionRoot><TooltipProvider delayDuration={600} skipDelayDuration={300}><App /></TooltipProvider></MotionRoot>);
