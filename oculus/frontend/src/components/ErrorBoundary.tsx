import { Component, type ErrorInfo, type ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('ReconVision UI error', error, info.componentStack);
  }

  render() {
    if (!this.state.error) {
      return this.props.children;
    }

    return (
      <div className="flex h-screen items-center justify-center p-6" style={{ background: 'var(--bg-void)', color: 'var(--text-pri)' }}>
        <div className="hud-border max-w-xl p-5" style={{ background: 'var(--bg-panel)' }}>
          <div style={{ color: 'var(--red)', fontFamily: 'var(--font-ui)', fontSize: 24, fontWeight: 700 }}>
            ReconVision UI recovered
          </div>
          <p className="mt-2 text-xs" style={{ color: 'var(--text-sec)', lineHeight: 1.6 }}>
            A malformed result caused the interface to stop rendering. Reload to continue with a clean UI state.
          </p>
          <pre className="mt-3 overflow-auto p-3 text-xs" style={{ background: 'var(--bg-deep)', color: 'var(--text-code)' }}>
            {this.state.error.message}
          </pre>
          <button
            className="mt-4 px-4 py-2 text-xs"
            style={{ background: 'var(--green)', color: '#00150a', fontWeight: 700, letterSpacing: '0.08em' }}
            onClick={() => window.location.reload()}
          >
            RELOAD APP
          </button>
        </div>
      </div>
    );
  }
}
