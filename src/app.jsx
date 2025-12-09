import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import wordCount from 'word-count';
import constants from '../shared/constants.json';

const difficulties = [
  '高校生の定期テストレベル',
  '共通テストレベル',
  '二次試験初級レベル',
  '二次試験上級レベル',
];

const { MAX_WORD_COUNT } = constants;

const defaultLongForm = {
  wordCount: 400,
  difficulty: difficulties[0],
  questionTypes: {
    grammarChoice: 1,
    vocabChoice: 1,
    contentChoice: 1,
    ordering: 0,
    grammarWrite: 0,
    vocabWrite: 0,
    translation: 1,
  },
  theme: 'Technology and education',
};

const defaultEssayForm = { theme: '自由テーマ', content: '' };

const countWords = (text = '') => {
  return wordCount(text || '');
};

const fetchJson = async (url, options = {}) => {
  const { headers, ...restOptions } = options;
  const res = await fetch(url, {
    ...restOptions,
    headers: { 'Content-Type': 'application/json', ...(headers || {}) },
  });
  if (!res.ok) {
    const detail = await res.json().catch(() => ({}));
    throw new Error(detail.message || 'リクエストに失敗しました');
  }
  return res.json();
};

const saveLocal = (key, value) => localStorage.setItem(key, JSON.stringify(value));
const readLocal = (key, fallback) => {
  try {
    const data = JSON.parse(localStorage.getItem(key));
    return data ?? fallback;
  } catch (e) {
    return fallback;
  }
};

const Label = ({ title, children }) => (
  <label className="field">
    <span>{title}</span>
    {children}
  </label>
);

function Login({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const user = await fetchJson('/api/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      });
      onLogin(user);
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <form className="card" onSubmit={submit}>
      <h2>ログイン</h2>
      <Label title="ユーザーID">
        <input value={username} onChange={(e) => setUsername(e.target.value)} required />
      </Label>
      <Label title="パスワード">
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
      </Label>
      {error && <div className="error">{error}</div>}
      <button type="submit" className="primary">
        ログイン
      </button>
    </form>
  );
}

function QueueInfo({ queue }) {
  return (
    <div className="card">
      <h3>待機リスト / レート情報</h3>
      <div className="stats-grid">
        <div>
          <p>問題作成待機: {queue.generationQueue}</p>
          <p>直近1分の作成: {queue.generationRecent}</p>
        </div>
        <div>
          <p>添削待機: {queue.reviewQueue}</p>
          <p>直近1分の添削: {queue.reviewRecent}</p>
        </div>
        <div>
          <p>作成処理/秒: {queue.limits.longPerSecond}</p>
          <p>添削処理/秒: {queue.limits.reviewPerSecond}</p>
        </div>
        <div>
          <p>待機閾値/分: {queue.limits.thresholdPerMinute}</p>
        </div>
      </div>
    </div>
  );
}

function UserAdmin({ me, users, onRefresh, config }) {
  const [form, setForm] = useState({
    username: '',
    password: '',
    displayName: '',
    accessRole: 'limited',
    dailyLimit: 10,
    priority: 'normal',
    userType: 'user',
    proAccess: false,
  });
  const [limits, setLimits] = useState(config);
  useEffect(() => setLimits(config), [config]);

  const createUser = async (e) => {
    e.preventDefault();
    await fetchJson('/api/users', {
      method: 'POST',
      headers: { 'x-user-type': me.userType },
      body: JSON.stringify(form),
    });
    setForm({
      username: '',
      password: '',
      displayName: '',
      accessRole: 'limited',
      dailyLimit: 10,
      priority: 'normal',
      userType: 'user',
      proAccess: false,
    });
    onRefresh();
  };

  const updateUser = async (id, field, value) => {
    await fetchJson(`/api/users/${id}`, {
      method: 'PUT',
      headers: { 'x-user-type': me.userType },
      body: JSON.stringify({ [field]: value }),
    });
    onRefresh();
  };

  const updateLimits = async (e) => {
    e.preventDefault();
    await fetchJson('/api/config', {
      method: 'POST',
      headers: { 'x-user-type': me.userType },
      body: JSON.stringify(limits),
    });
    onRefresh(true);
  };

  const disabled = me.userType === 'helper';

  return (
    <div className="grid">
      <div className="card">
        <h3>利用者管理</h3>
        <div className="user-list">
          {users.map((u) => (
            <div key={u.id} className="user-row">
              <div>
                <strong>{u.displayName}</strong> ({u.username}) [{u.userType}]
              </div>
              <div className="row">
                <label>
                  アクセス:
                  <select
                    value={u.accessRole}
                    disabled={disabled}
                    onChange={(e) => updateUser(u.id, 'accessRole', e.target.value)}
                  >
                    <option value="unlimited">無制限</option>
                    <option value="limited">制限付き</option>
                  </select>
                </label>
                <label>
                  1日上限:
                  <input
                    type="number"
                    value={u.dailyLimit || ''}
                    disabled={disabled}
                    onChange={(e) => updateUser(u.id, 'dailyLimit', Number(e.target.value))}
                  />
                </label>
                <label>
                  優先度:
                  <select
                    value={u.priority}
                    disabled={disabled}
                    onChange={(e) => updateUser(u.id, 'priority', e.target.value)}
                  >
                    <option value="priority">優先</option>
                    <option value="normal">通常</option>
                  </select>
                </label>
                <label>
                  Pro:
                  <input
                    type="checkbox"
                    checked={u.proAccess}
                    disabled={disabled}
                    onChange={(e) => updateUser(u.id, 'proAccess', e.target.checked)}
                  />
                </label>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="card">
        <h3>新規利用者登録</h3>
        <form className="compact-grid" onSubmit={createUser}>
          <Label title="ユーザーID">
            <input
              required
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              disabled={me.userType !== 'admin'}
            />
          </Label>
          <Label title="パスワード">
            <input
              required
              type="password"
              value={form.password}
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              disabled={me.userType !== 'admin'}
            />
          </Label>
          <Label title="表示名">
            <input
              value={form.displayName}
              onChange={(e) => setForm({ ...form, displayName: e.target.value })}
              disabled={me.userType !== 'admin'}
            />
          </Label>
          <Label title="アクセスロール">
            <select
              value={form.accessRole}
              onChange={(e) => setForm({ ...form, accessRole: e.target.value })}
              disabled={me.userType !== 'admin'}
            >
              <option value="unlimited">無制限</option>
              <option value="limited">制限付き</option>
            </select>
          </Label>
          <Label title="1日上限">
            <input
              type="number"
              value={form.dailyLimit}
              onChange={(e) => setForm({ ...form, dailyLimit: Number(e.target.value) })}
              disabled={me.userType !== 'admin'}
            />
          </Label>
          <Label title="優先度">
            <select
              value={form.priority}
              onChange={(e) => setForm({ ...form, priority: e.target.value })}
              disabled={me.userType !== 'admin'}
            >
              <option value="priority">優先</option>
              <option value="normal">通常</option>
            </select>
          </Label>
          <Label title="利用者種別">
            <select
              value={form.userType}
              onChange={(e) => setForm({ ...form, userType: e.target.value })}
              disabled={me.userType !== 'admin'}
            >
              <option value="admin">管理者</option>
              <option value="helper">ヘルパー</option>
              <option value="user">一般</option>
            </select>
          </Label>
          <label className="row">
            <input
              type="checkbox"
              checked={form.proAccess}
              onChange={(e) => setForm({ ...form, proAccess: e.target.checked })}
              disabled={me.userType !== 'admin'}
            />
            Proアクセスを付与
          </label>
          <button className="primary" type="submit" disabled={me.userType !== 'admin'}>
            登録
          </button>
        </form>
      </div>
      <div className="card">
        <h3>レート制限設定</h3>
        <form className="compact-grid" onSubmit={updateLimits}>
          <Label title="問題作成/秒">
            <input
              type="number"
              value={limits.longPerSecond}
              disabled={me.userType !== 'admin'}
              onChange={(e) => setLimits({ ...limits, longPerSecond: Number(e.target.value) })}
            />
          </Label>
          <Label title="添削/秒">
            <input
              type="number"
              value={limits.reviewPerSecond}
              disabled={me.userType !== 'admin'}
              onChange={(e) => setLimits({ ...limits, reviewPerSecond: Number(e.target.value) })}
            />
          </Label>
          <Label title="直近1分しきい値">
            <input
              type="number"
              value={limits.thresholdPerMinute}
              disabled={me.userType !== 'admin'}
              onChange={(e) => setLimits({ ...limits, thresholdPerMinute: Number(e.target.value) })}
            />
          </Label>
          <button className="primary" type="submit" disabled={me.userType !== 'admin'}>
            保存
          </button>
        </form>
      </div>
    </div>
  );
}

function LongTask({ form, setForm, onSubmit, saving, onPause, onResume }) {
  const updateType = (key, value) => {
    setForm({
      ...form,
      questionTypes: { ...form.questionTypes, [key]: Number(value) },
    });
  };
  return (
    <div className="card">
      <h3>長文問題作成</h3>
      <div className="grid">
        <Label title={`語数 (最大${MAX_WORD_COUNT})`}>
          <input
            type="number"
            min="1"
            max={MAX_WORD_COUNT}
            value={form.wordCount}
            onChange={(e) => {
              const next = Math.max(0, Math.min(Number(e.target.value) || 0, MAX_WORD_COUNT));
              setForm({ ...form, wordCount: next });
            }}
          />
        </Label>
        <Label title="難易度">
          <select
            value={form.difficulty}
            onChange={(e) => setForm({ ...form, difficulty: e.target.value })}
          >
            {difficulties.map((d) => (
              <option key={d}>{d}</option>
            ))}
          </select>
        </Label>
        <Label title="テーマ">
          <input
            value={form.theme}
            onChange={(e) => setForm({ ...form, theme: e.target.value })}
            placeholder="テーマを入力"
          />
        </Label>
      </div>
      <div className="question-types">
        {Object.entries(form.questionTypes).map(([key, val]) => (
          <label key={key}>
            {key}
            <input
              type="number"
              min="0"
              value={val}
              onChange={(e) => updateType(key, e.target.value)}
            />
          </label>
        ))}
      </div>
      <div className="row">
        <button onClick={onSubmit} className="primary" disabled={saving}>
          作成する
        </button>
        <button type="button" onClick={onPause}>
          中断して保存
        </button>
        <button type="button" onClick={onResume}>
          保存分を再開
        </button>
      </div>
    </div>
  );
}

function EssayTask({ form, setForm, onSubmit, onPause, onResume }) {
  const wordCount = countWords(form.content);
  return (
    <div className="card">
      <h3>自由英作文</h3>
      <Label title="テーマ">
        <input
          value={form.theme}
          onChange={(e) => setForm({ ...form, theme: e.target.value })}
          placeholder="テーマを入力"
        />
      </Label>
      <Label title="回答">
        <textarea
          rows="5"
          value={form.content}
          onChange={(e) => setForm({ ...form, content: e.target.value })}
        />
      </Label>
      <div className="row">
        <small>入力語数: {wordCount}</small>
      </div>
      <div className="row">
        <button className="primary" onClick={onSubmit}>
          添削を依頼
        </button>
        <button type="button" onClick={onPause}>
          中断して保存
        </button>
        <button type="button" onClick={onResume}>
          保存分を再開
        </button>
      </div>
    </div>
  );
}

function TaskBoard({ tasks, onSubmitAnswers, drafts, setDrafts }) {
  const renderStatus = (task) => {
    switch (task.status) {
      case 'awaiting_answers':
        return '回答待ち';
      case 'queued_generation':
        return '生成待機';
      case 'queued_review':
        return '添削待機';
      case 'review_complete':
        return '添削完了';
      default:
        return task.status || '処理中';
    }
  };

  return (
    <div className="card">
      <h3>タスク一覧 / 再開</h3>
      {tasks.map((task) => (
        <div key={task.id} className="task">
          <div className="task-header">
            <div>
              <strong>{task.type === 'long' ? '長文' : '英作文'}</strong> /{' '}
              {new Date(task.createdAt).toLocaleString()}
            </div>
            <div className="status">{renderStatus(task)}</div>
          </div>
          {task.generated && (
            <details>
              <summary>英文</summary>
              <p>{task.generated}</p>
            </details>
          )}
          {task.questions?.length > 0 && (
            <div>
              <h4>設問</h4>
              {task.questions.map((q, idx) => (
                <div key={q.id} className="question">
                  <p>
                    {idx + 1}. {q.prompt}
                  </p>
                  {task.status === 'awaiting_answers' && (
                    <input
                      value={drafts[task.id]?.[idx] || ''}
                      onChange={(e) =>
                        setDrafts({
                          ...drafts,
                          [task.id]: {
                            ...(drafts[task.id] || {}),
                            [idx]: e.target.value,
                          },
                        })
                      }
                      placeholder="回答を入力"
                    />
                  )}
                  {task.answers?.[idx] && <p className="answer">回答: {task.answers[idx]}</p>}
                </div>
              ))}
              {task.status === 'awaiting_answers' && (
                <button
                  className="primary"
                  onClick={() =>
                    onSubmitAnswers(task.id, task.questions.map((_, idx) => drafts[task.id]?.[idx] || ''))
                  }
                >
                  添削を依頼
                </button>
              )}
            </div>
          )}
          {task.correction && (
            <div className="correction">
              <h4>添削</h4>
              <p>{task.correction.translation}</p>
              <p>{task.correction.keyPoints}</p>
              <p>{task.correction.grammar}</p>
              <p>{task.correction.scoring}</p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function App() {
  const [user, setUser] = useState(() => readLocal('sessionUser', null));
  const [users, setUsers] = useState([]);
  const [config, setConfig] = useState({
    longPerSecond: 1,
    reviewPerSecond: 1,
    thresholdPerMinute: 5,
  });
  const [tasks, setTasks] = useState([]);
  const [queue, setQueue] = useState({
    generationQueue: 0,
    reviewQueue: 0,
    generationRecent: 0,
    reviewRecent: 0,
    limits: config,
  });
  const [longForm, setLongForm] = useState(() => readLocal('longForm', defaultLongForm));
  const [essayForm, setEssayForm] = useState(() => readLocal('essayForm', defaultEssayForm));
  const [message, setMessage] = useState('');
  const [answerDrafts, setAnswerDrafts] = useState({});

  const loggedIn = !!user;

  const loadUsers = async () => {
    if (!user || (user.userType !== 'admin' && user.userType !== 'helper')) return;
    const res = await fetchJson('/api/users', { headers: { 'x-user-type': user.userType } });
    setUsers(res);
  };

  const loadConfig = async () => {
    if (!user || (user.userType !== 'admin' && user.userType !== 'helper')) return;
    const res = await fetchJson('/api/config', { headers: { 'x-user-type': user.userType } });
    setConfig(res);
    setQueue((q) => ({ ...q, limits: res }));
  };

  const loadTasks = async () => {
    if (!user) return;
    const res = await fetchJson(`/api/tasks?userId=${user.id}`);
    setTasks(res);
  };

  const loadQueue = async () => {
    const res = await fetchJson('/api/queue');
    setQueue(res);
  };

  useEffect(() => {
    if (!loggedIn) return;
    loadUsers();
    loadConfig();
    loadTasks();
    loadQueue();
    const interval = setInterval(() => {
      loadTasks();
      loadQueue();
    }, 5000);
    return () => clearInterval(interval);
  }, [loggedIn]);

  const handleLogin = (data) => {
    setUser(data);
    saveLocal('sessionUser', data);
    loadTasks();
  };

  const createLongTask = async () => {
    setMessage('');
    if (!longForm.wordCount || !longForm.difficulty) {
      setMessage('必須項目を入力してください');
      return;
    }
    const resp = await fetchJson('/api/longtasks', {
      method: 'POST',
      body: JSON.stringify({ ...longForm, userId: user.id }),
    });
    setMessage(resp.queued ? '待機リストに入りました' : '問題を作成しました');
    await loadTasks();
  };

  const submitAnswers = async (taskId, answers) => {
    const hasEmpty = answers.some((a) => !a.trim());
    if (hasEmpty) {
      setMessage('空白の回答があります');
      return;
    }
    const resp = await fetchJson(`/api/longtasks/${taskId}/submit`, {
      method: 'POST',
      body: JSON.stringify({ answers, userId: user.id }),
    });
    setMessage(resp.queued ? '添削待機リストに追加しました' : '添削完了');
    await loadTasks();
  };

  const createEssay = async () => {
    setMessage('');
    if (!essayForm.content.trim()) {
      setMessage('回答を入力してください');
      return;
    }
    const resp = await fetchJson('/api/essay', {
      method: 'POST',
      body: JSON.stringify({ ...essayForm, userId: user.id }),
    });
    setMessage('添削を受け付けました');
    await loadTasks();
    if (resp.correction) {
      setTasks((prev) =>
        prev.map((t) => (t.id === resp.taskId ? { ...t, correction: resp.correction } : t))
      );
    }
  };

  const pauseLong = () => {
    saveLocal('longForm', longForm);
    setMessage('長文問題の入力を保存しました');
  };
  const resumeLong = () => setLongForm(readLocal('longForm', longForm));
  const pauseEssay = () => {
    saveLocal('essayForm', essayForm);
    setMessage('英作文の入力を保存しました');
  };
  const resumeEssay = () => setEssayForm(readLocal('essayForm', essayForm));

  const logout = () => {
    localStorage.removeItem('sessionUser');
    setUser(null);
  };

  return (
    <div className="page">
      <header>
        <div>
          <h1>English Learning System</h1>
          <p>長文問題作成・自由英作文の添削</p>
        </div>
        {loggedIn && (
          <div>
            <p>
              {user.displayName} ({user.userType}) {user.proAccess ? ' / Gemini 2.5 Pro' : ''}
            </p>
            <button onClick={logout}>ログアウト</button>
          </div>
        )}
      </header>
      {!loggedIn && <Login onLogin={handleLogin} />}
      {loggedIn && (
        <>
          <div className="grid">
            <LongTask
              form={longForm}
              setForm={setLongForm}
              onSubmit={createLongTask}
              onPause={pauseLong}
              onResume={resumeLong}
            />
            <EssayTask
              form={essayForm}
              setForm={setEssayForm}
              onSubmit={createEssay}
              onPause={pauseEssay}
              onResume={resumeEssay}
            />
          </div>
          <QueueInfo queue={queue} />
          {message && <div className="notice">{message}</div>}
          {(user.userType === 'admin' || user.userType === 'helper') && (
            <UserAdmin
              me={user}
              users={users}
              config={config}
              onRefresh={(reloadConfig) => {
                loadUsers();
                if (reloadConfig) loadConfig();
              }}
            />
          )}
          <TaskBoard
            tasks={tasks}
            onSubmitAnswers={submitAnswers}
            drafts={answerDrafts}
            setDrafts={setAnswerDrafts}
          />
        </>
      )}
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
