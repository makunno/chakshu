import React, { useState } from 'react';
import type { Report } from '../types';
import './ReportPreview.css';

interface ReportPreviewProps {
  report: Report;
  onClose: () => void;
}

const ReportPreview: React.FC<ReportPreviewProps> = ({ report, onClose }) => {
  const [activeSection, setActiveSection] = useState<string>('full');

  const downloadHTML = () => {
    const blob = new Blob([report.content], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.name.replace(/\s+/g, '_')}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="report-preview-overlay">
      <div className="report-preview">
        <div className="preview-header">
          <h2>Report Preview</h2>
          <div className="preview-actions">
            <button onClick={downloadHTML} className="btn-download">
              Download HTML
            </button>
            <button onClick={onClose} className="btn-close">
              ✕
            </button>
          </div>
        </div>

        <div className="preview-nav">
          <button
            className={activeSection === 'full' ? 'active' : ''}
            onClick={() => setActiveSection('full')}
          >
            Full Report
          </button>
          {report.sections.map(section => (
            <button
              key={section.id}
              className={activeSection === section.id ? 'active' : ''}
              onClick={() => setActiveSection(section.id)}
            >
              {section.title}
            </button>
          ))}
        </div>

        <div className="preview-content">
          {activeSection === 'full' ? (
            <iframe
              title="Report Preview"
              srcDoc={report.content}
              style={{ width: '100%', height: '100%', border: 'none' }}
            />
          ) : (
            <div className="section-preview">
              {report.sections
                .filter(s => s.id === activeSection)
                .map(section => (
                  <div key={section.id}>
                    <h3>{section.title}</h3>
                    <div
                      dangerouslySetInnerHTML={{
                        __html: section.content || ''
                      }}
                    />
                  </div>
                ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ReportPreview;
