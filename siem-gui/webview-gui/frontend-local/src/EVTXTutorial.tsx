import { useState } from 'react';
import { X, Upload, ChevronRight, FileText } from 'lucide-react';
import './EVTXTutorial.css';

interface EVTXTutorialProps {
  fileName: string;
  onClose: () => void;
  onUploadAnother: () => void;
}

export function EVTXTutorial({ fileName, onClose, onUploadAnother }: EVTXTutorialProps) {
  const [step, setStep] = useState(1);

  const steps = [
    {
      title: 'Open Event Viewer',
      description: 'Press Windows Key + R, type "eventvwr.msc", and press Enter',
      image: '/images/evtx/step1-eventviewer-open.png'
    },
    {
      title: 'Navigate to Your Log',
      description: 'Expand "Windows Logs" and select the log you want to export (Security, System, or Application)',
      image: '/images/evtx/step2-navigate-log.png'
    },
    {
      title: 'Save the Log',
      description: 'Right-click on the log, select "Save All Events As...", and choose a location to save',
      image: '/images/evtx/step3-save-menu.png'
    },
    {
      title: 'Choose TXT Format',
      description: 'In the Save dialog, set format to "Text (Tab-Delimited) (*.txt)" and click Save',
      image: '/images/evtx/step4-choose-format.png'
    },
    {
      title: 'Upload the TXT File',
      description: 'Upload the exported .txt file to Cyber Chakshu SIEM for analysis',
      image: '/images/evtx/step5-upload.png'
    }
  ];

  return (
    <div className="evtx-tutorial-overlay">
      <div className="evtx-tutorial-modal">
        <div className="tutorial-header">
          <div className="tutorial-icon">
            <FileText size={32} />
          </div>
          <div className="tutorial-title-section">
            <h2>How to Export Windows Event Logs as TXT</h2>
            <p>Your file "{fileName}" is in EVTX format which cannot be processed directly.</p>
          </div>
          <button className="close-btn" onClick={onClose}>
            <X size={24} />
          </button>
        </div>

        <div className="tutorial-progress">
          {steps.map((_, idx) => (
            <div 
              key={idx} 
              className={`progress-dot ${idx + 1 <= step ? 'active' : ''}`}
              onClick={() => setStep(idx + 1)}
            />
          ))}
        </div>

        <div className="tutorial-content">
          <div className="tutorial-image">
            {steps[step - 1].image && (
              <div className="image-placeholder">
                <img 
                  src={steps[step - 1].image} 
                  alt={steps[step - 1].title}
                />
              </div>
            )}
          </div>

          <div className="tutorial-text">
            <div className="step-indicator">Step {step} of {steps.length}</div>
            <h3>{steps[step - 1].title}</h3>
            <p>{steps[step - 1].description}</p>

            {step === 1 && (
              <div className="command-box">
                <strong>Quick Command:</strong>
                <code>eventvwr.msc</code>
              </div>
            )}
          </div>
        </div>

        <div className="tutorial-nav">
          <button 
            className="btn btn-secondary"
            onClick={() => setStep(Math.max(1, step - 1))}
            disabled={step === 1}
          >
            Previous
          </button>
          
          <div className="step-dots">
            {steps.map((_, idx) => (
              <button
                key={idx}
                className={`step-dot ${idx + 1 === step ? 'active' : ''}`}
                onClick={() => setStep(idx + 1)}
              >
                {idx + 1}
              </button>
            ))}
          </div>

          {step < steps.length ? (
            <button 
              className="btn btn-primary"
              onClick={() => setStep(step + 1)}
            >
              Next
              <ChevronRight size={18} />
            </button>
          ) : (
            <button 
              className="btn btn-primary"
              onClick={onUploadAnother}
            >
              <Upload size={18} />
              Upload TXT File
            </button>
          )}
        </div>

        <div className="tutorial-footer">
          <button className="btn btn-secondary" onClick={onUploadAnother}>
            <Upload size={16} />
            Upload Another File
          </button>
        </div>
      </div>
    </div>
  );
}
