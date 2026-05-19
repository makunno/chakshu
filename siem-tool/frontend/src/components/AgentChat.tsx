import React, { useState, useEffect, useRef } from 'react';
import { socAnalystAgent } from '../agent';
import { reportGenerator } from '../report';
import type { ParseResponse, CorrelateResponse, AgentMessage, Report } from '../types';
import './AgentChat.css';

interface AgentChatProps {
  parsedData: ParseResponse | null;
  correlateData?: CorrelateResponse;
  onGenerateReport?: (report: Report) => void;
}

const AgentChat: React.FC<AgentChatProps> = ({ parsedData, correlateData, onGenerateReport }) => {
  const [messages, setMessages] = useState<AgentMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Initialize agent when parsed data is available
    if (parsedData) {
      socAnalystAgent.initialize(parsedData, correlateData);
      addSystemMessage('Agent initialized. Ready for security analysis.');
    }
  }, [parsedData, correlateData]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const addSystemMessage = (content: string) => {
    const msg: AgentMessage = {
      id: `msg_${Date.now()}`,
      role: 'system',
      content,
      timestamp: new Date().toISOString()
    };
    setMessages(prev => [...prev, msg]);
  };

  const handleSendMessage = async () => {
    if (!inputValue.trim() || isProcessing) return;

    const userMessage = inputValue.trim();
    setInputValue('');
    setIsProcessing(true);

    try {
      // Add user message
      const userMsg: AgentMessage = {
        id: `msg_${Date.now()}`,
        role: 'user',
        content: userMessage,
        timestamp: new Date().toISOString()
      };
      setMessages(prev => [...prev, userMsg]);

      // Process with agent
      const agentResponse = await socAnalystAgent.processMessage(userMessage);
      setMessages(prev => [...prev, agentResponse]);

    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'An error occurred';
      addSystemMessage(`Error: ${errorMsg}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleGenerateReport = async (templateId: string) => {
    if (!parsedData) {
      addSystemMessage('No log data available for report generation.');
      return;
    }

    try {
      const report = reportGenerator.generateReport(
        { logData: parsedData, correlateData },
        templateId
      );

      if (onGenerateReport) {
        onGenerateReport(report);
      }

      addSystemMessage(`Report generated: ${report.name}`);
      setShowTemplates(false);
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Failed to generate report';
      addSystemMessage(`Report Error: ${errorMsg}`);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const templates = reportGenerator.getTemplates();

  return (
    <div className="agent-chat">
      <div className="chat-header">
        <h3>SOC Analyst AI</h3>
        <div className="header-actions">
          <button
            className="btn-icon"
            onClick={() => setShowTemplates(!showTemplates)}
            title="Generate Report"
          >
            📄
          </button>
          <button
            className="btn-icon"
            onClick={() => {
              socAnalystAgent.clearConversation();
              setMessages([]);
              addSystemMessage('Conversation cleared.');
            }}
            title="Clear Chat"
          >
            🗑️
          </button>
        </div>
      </div>

      {showTemplates && (
        <div className="templates-dropdown">
          <h4>Generate Report</h4>
          {templates.map(template => (
            <button
              key={template.id}
              className="template-btn"
              onClick={() => handleGenerateReport(template.id)}
            >
              {template.name}
            </button>
          ))}
        </div>
      )}

      <div className="chat-messages">
        {messages.map(msg => (
          <div key={msg.id} className={`message ${msg.role}`}>
            <div className="message-header">
              <span className="sender">
                {msg.role === 'user' ? 'You' : msg.role === 'agent' ? 'AI' : 'System'}
              </span>
              <span className="time">
                {new Date(msg.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <div className="message-content">
              {msg.content}
              {msg.dataRequests && msg.dataRequests.length > 0 && (
                <div className="data-requests">
                  <small>Data requests: {msg.dataRequests.length}</small>
                </div>
              )}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </div>

      <div className="chat-input">
        <input
          type="text"
          value={inputValue}
          onChange={e => setInputValue(e.target.value)}
          onKeyPress={handleKeyPress}
          placeholder="Ask about security events, attacks, or request a report..."
          disabled={isProcessing || !parsedData}
        />
        <button
          onClick={handleSendMessage}
          disabled={isProcessing || !inputValue.trim() || !parsedData}
        >
          {isProcessing ? '⏳' : 'Send'}
        </button>
      </div>

      <div className="chat-hints">
        <small>
          Try: "Show me statistics", "What attacks were detected?", "Generate security report"
        </small>
      </div>
    </div>
  );
};

export default AgentChat;
