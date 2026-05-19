import { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Sparkles, X, ChevronDown, Shield, FileText, ThumbsUp, ThumbsDown } from 'lucide-react';
import { getSocAnalystChat, analyzeLogWithAI, submitFeedback, type FeedbackRequest } from '../api';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  isStreaming?: boolean;
  originalPrompt?: string;
  feedbackSubmitted?: boolean;
  feedbackRating?: number;
}

interface LogContext {
  logEntry: string;
  logType: string;
  detectedType?: string;
}

interface SOCAnalystChatProps {
  logContext?: LogContext | null;
  currentData?: any;
  onClose?: () => void;
}

export function SOCAnalystChat({ logContext, currentData, onClose }: SOCAnalystChatProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isExpanded, setIsExpanded] = useState(true);
  const [selectedLogForAnalysis, setSelectedLogForAnalysis] = useState<LogContext | null>(logContext || null);
  const [feedbackModal, setFeedbackModal] = useState<{messageId: string; message: string; originalPrompt: string} | null>(null);
  const [feedbackText, setFeedbackText] = useState('');
  const [isSubmittingFeedback, setIsSubmittingFeedback] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Initial greeting
  useEffect(() => {
    if (messages.length === 0) {
      const greeting: Message = {
        id: 'greeting',
        role: 'assistant',
        content: "Hello! I'm your SOC Analyst AI. I can help you:\n\n" +
                "- Analyze suspicious log entries\n" +
                "- Explain attack patterns and techniques\n" +
                "- Identify security threats\n" +
                "- Provide incident response guidance\n\n" +
                "How can I assist you today?\n\n" +
                "P.S. Your feedback helps me improve! Use the like/dislike buttons on my responses.",
        timestamp: new Date(),
        originalPrompt: "You are a SOC Analyst AI assistant.",
      };
      setMessages([greeting]);
    }
  }, []);

  // Auto-scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Focus input when expanded
  useEffect(() => {
    if (isExpanded && inputRef.current) {
      inputRef.current.focus();
    }
  }, [isExpanded]);

  // Handle log analysis context
  useEffect(() => {
    if (logContext && logContext.logEntry) {
      setSelectedLogForAnalysis(logContext);
      handleAnalyzeLog(logContext);
    }
  }, [logContext]);

  const handleAnalyzeLog = async (context: LogContext) => {
    const prompt = `Analyze this ${context.logType} log entry for security threats.`;
    
    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: `Please analyze this ${context.logType} log:\n\n${context.logEntry}`,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setIsLoading(true);

    try {
      const response = await analyzeLogWithAI(context.logEntry, context.logType);
      
      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: response.analysis,
        timestamp: new Date(),
        originalPrompt: prompt,
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (error) {
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: "Sorry, I couldn't analyze that log. The SOC Analyst AI service might be unavailable. Please try again later.",
        timestamp: new Date(),
        originalPrompt: prompt,
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const prompt = "You are a SOC Analyst AI assistant.";
    
    const userMessage: Message = {
      id: Date.now().toString(),
      role: 'user',
      content: input,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await getSocAnalystChat(
        input, 
        messages.map(m => ({role: m.role, content: m.content})),
        currentData
      );
      
      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: response,
        timestamp: new Date(),
        originalPrompt: prompt,
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (error) {
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: "Sorry, I'm having trouble connecting to the SOC Analyst AI service. Please ensure the LLM server is running on port 8000.",
        timestamp: new Date(),
        originalPrompt: prompt,
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFeedback = async (messageId: string, rating: 1 | 5) => {
    const message = messages.find(m => m.id === messageId);
    if (!message || message.feedbackSubmitted) return;

    if (rating === 1) {
      setFeedbackModal({
        messageId,
        message: message.content,
        originalPrompt: message.originalPrompt || '',
      });
      return;
    }

    await submitFeedbackInternal(messageId, rating, message.content, message.originalPrompt || '', '');
  };

  const submitFeedbackInternal = async (
    messageId: string, 
    rating: 1 | 5, 
    llmResponse: string, 
    originalPrompt: string,
    feedbackText: string
  ) => {
    setIsSubmittingFeedback(true);
    
    try {
      const feedback: FeedbackRequest = {
        message_id: messageId,
        rating,
        feedback_text: feedbackText,
        original_prompt: originalPrompt,
        llm_response: llmResponse,
        log_context: selectedLogForAnalysis ? `${selectedLogForAnalysis.logType}: ${selectedLogForAnalysis.logEntry}` : '',
      };

      await submitFeedback(feedback);

      setMessages(prev => prev.map(m => 
        m.id === messageId 
          ? { ...m, feedbackSubmitted: true, feedbackRating: rating }
          : m
      ));
    } catch (error) {
      console.error('Failed to submit feedback:', error);
    } finally {
      setIsSubmittingFeedback(false);
      setFeedbackModal(null);
      setFeedbackText('');
    }
  };

  const handleSubmitFeedbackWithCorrection = () => {
    if (!feedbackModal) return;
    
    const message = messages.find(m => m.id === feedbackModal.messageId);
    if (!message) return;

    submitFeedbackInternal(
      feedbackModal.messageId,
      1,
      message.content,
      feedbackModal.originalPrompt,
      feedbackText
    );
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const clearChat = () => {
    setMessages([]);
    setSelectedLogForAnalysis(null);
  };

  const formatMessage = (content: string) => {
    return content
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/```([\s\S]*?)```/g, '<pre style="background-color: #1f2937; padding: 8px; border-radius: 6px; font-size: 12px; overflow-x: auto;">$1</pre>')
      .replace(/`([^`]+)`/g, '<code style="background-color: #374151; padding: 2px 4px; border-radius: 4px; font-size: 12px;">$1</code>')
      .replace(/\n/g, '<br />');
  };

  // Minimized state - show round floating button
  if (!isExpanded) {
    return (
      <button
        onClick={() => setIsExpanded(true)}
        style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          width: '56px',
          height: '56px',
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #9333ea 0%, #2563eb 100%)',
          color: 'white',
          border: 'none',
          boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.3)',
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 9999,
          transition: 'transform 0.2s ease'
        }}
        onMouseEnter={(e) => e.currentTarget.style.transform = 'scale(1.1)'}
        onMouseLeave={(e) => e.currentTarget.style.transform = 'scale(1)'}
        title="Chat with SOC Analyst AI"
      >
        <Bot style={{ width: '28px', height: '28px' }} />
      </button>
    );
  }

  return (
    <div style={{
      position: 'fixed',
      bottom: '24px',
      right: '24px',
      width: '384px',
      height: '600px',
      backgroundColor: '#111827',
      borderRadius: '16px',
      boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
      display: 'flex',
      flexDirection: 'column',
      zIndex: 10000,
      border: '1px solid #374151',
      overflow: 'hidden'
    }}>
      {/* Feedback Modal */}
      {feedbackModal && (
        <div style={{
          position: 'absolute',
          inset: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.5)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 50,
          borderRadius: '16px'
        }}>
          <div style={{
            backgroundColor: '#1f2937',
            padding: '16px',
            borderRadius: '12px',
            margin: '16px',
            width: '100%',
            maxWidth: '320px',
            border: '1px solid #4b5563'
          }}>
            <h4 style={{ color: 'white', fontWeight: 600, marginBottom: '8px' }}>Help Improve the AI</h4>
            <p style={{ color: '#d1d5db', fontSize: '14px', marginBottom: '12px' }}>
              What would have been a better response?
            </p>
            <textarea
              value={feedbackText}
              onChange={(e) => setFeedbackText(e.target.value)}
              placeholder="Enter your suggested response..."
              style={{
                width: '100%',
                backgroundColor: '#374151',
                border: '1px solid #4b5563',
                borderRadius: '8px',
                padding: '8px 12px',
                color: 'white',
                fontSize: '14px',
                marginBottom: '12px',
                height: '96px',
                resize: 'none'
              }}
            />
            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                onClick={() => { setFeedbackModal(null); setFeedbackText(''); }}
                style={{
                  flex: 1,
                  padding: '8px 12px',
                  backgroundColor: '#4b5563',
                  color: 'white',
                  border: 'none',
                  borderRadius: '8px',
                  fontSize: '14px',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleSubmitFeedbackWithCorrection}
                disabled={isSubmittingFeedback}
                style={{
                  flex: 1,
                  padding: '8px 12px',
                  backgroundColor: '#dc2626',
                  color: 'white',
                  border: 'none',
                  borderRadius: '8px',
                  fontSize: '14px',
                  cursor: isSubmittingFeedback ? 'not-allowed' : 'pointer',
                  opacity: isSubmittingFeedback ? 0.5 : 1
                }}
              >
                {isSubmittingFeedback ? 'Sending...' : 'Submit'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '16px',
        background: 'linear-gradient(135deg, #581c87 0%, #1e40af 100%)',
        borderTopLeftRadius: '16px',
        borderTopRightRadius: '16px',
        borderBottom: '1px solid #374151',
        flexShrink: 0
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{
            width: '32px',
            height: '32px',
            background: 'linear-gradient(135deg, #a855f7 0%, #3b82f6 100%)',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Shield style={{ width: '20px', height: '20px', color: 'white' }} />
          </div>
          <div>
            <h3 style={{ fontWeight: 600, color: 'white', margin: 0, fontSize: '16px' }}>SOC Analyst AI</h3>
            <p style={{ fontSize: '12px', color: '#d1d5db', margin: 0 }}>Powered by TinyLlama-1.1B</p>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
          <button
            onClick={clearChat}
            style={{
              padding: '8px',
              backgroundColor: 'transparent',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              color: '#d1d5db'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.1)'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
            title="Clear chat"
          >
            <Sparkles style={{ width: '16px', height: '16px' }} />
          </button>
          <button
            onClick={() => setIsExpanded(false)}
            style={{
              padding: '8px',
              backgroundColor: 'transparent',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              color: '#d1d5db'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.1)'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
            title="Minimize"
          >
            <ChevronDown style={{ width: '20px', height: '20px' }} />
          </button>
          {onClose && (
            <button
              onClick={onClose}
              style={{
                padding: '8px',
                backgroundColor: 'transparent',
                border: 'none',
                borderRadius: '8px',
                cursor: 'pointer',
                color: '#d1d5db'
              }}
              onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(255,255,255,0.1)'}
              onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
              title="Close"
            >
              <X style={{ width: '20px', height: '20px' }} />
            </button>
          )}
        </div>
      </div>

      {/* Selected log context */}
      {selectedLogForAnalysis && (
        <div style={{
          padding: '8px 16px',
          backgroundColor: 'rgba(234, 179, 8, 0.1)',
          borderBottom: '1px solid #374151'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <FileText style={{ width: '16px', height: '16px', color: '#eab308' }} />
              <span style={{ fontSize: '12px', color: '#fde047' }}>Analyzing log: {selectedLogForAnalysis.logType}</span>
            </div>
            <button
              onClick={() => setSelectedLogForAnalysis(null)}
              style={{
                fontSize: '12px',
                color: '#9ca3af',
                background: 'none',
                border: 'none',
                cursor: 'pointer'
              }}
              onMouseEnter={(e) => e.currentTarget.style.color = 'white'}
              onMouseLeave={(e) => e.currentTarget.style.color = '#9ca3af'}
            >
              Clear
            </button>
          </div>
        </div>
      )}

      {/* Messages */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '16px',
        display: 'flex',
        flexDirection: 'column',
        gap: '16px'
      }}>
        {messages.map((message) => (
          <div
            key={message.id}
            style={{
              display: 'flex',
              gap: '12px',
              flexDirection: message.role === 'user' ? 'row-reverse' : 'row'
            }}
          >
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0,
              background: message.role === 'user' 
                ? '#2563eb' 
                : 'linear-gradient(135deg, #9333ea 0%, #2563eb 100%)'
            }}>
              {message.role === 'user' ? (
                <User style={{ width: '16px', height: '16px', color: 'white' }} />
              ) : (
                <Bot style={{ width: '16px', height: '16px', color: 'white' }} />
              )}
            </div>
            <div style={{
              maxWidth: '80%',
              borderRadius: '16px',
              padding: '12px',
              backgroundColor: message.role === 'user' ? '#2563eb' : '#1f2937',
              color: message.role === 'user' ? 'white' : '#f3f4f6',
              border: message.role === 'user' ? 'none' : '1px solid #374151',
              borderBottomRightRadius: message.role === 'user' ? '4px' : '16px',
              borderBottomLeftRadius: message.role === 'user' ? '16px' : '4px'
            }}>
              <div 
                style={{ fontSize: '14px', lineHeight: 1.6 }}
                dangerouslySetInnerHTML={{ __html: formatMessage(message.content) }}
              />
              <div style={{ 
                fontSize: '12px', 
                marginTop: '4px',
                color: message.role === 'user' ? '#bfdbfe' : '#6b7280'
              }}>
                {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              </div>
              
              {/* Feedback buttons for assistant messages */}
              {message.role === 'assistant' && !message.isStreaming && (
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  marginTop: '8px',
                  paddingTop: '8px',
                  borderTop: '1px solid #374151'
                }}>
                  {message.feedbackSubmitted ? (
                    <span style={{ fontSize: '12px', color: '#4ade80' }}>
                      {message.feedbackRating === 5 ? 'Thanks!' : 'Feedback received'}
                    </span>
                  ) : (
                    <>
                      <button
                        onClick={() => handleFeedback(message.id, 5)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '4px 8px',
                          borderRadius: '6px',
                          backgroundColor: '#374151',
                          border: 'none',
                          color: '#d1d5db',
                          fontSize: '12px',
                          cursor: 'pointer'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.backgroundColor = 'rgba(34, 197, 94, 0.2)';
                          e.currentTarget.style.color = '#4ade80';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.backgroundColor = '#374151';
                          e.currentTarget.style.color = '#d1d5db';
                        }}
                        title="Good response"
                      >
                        <ThumbsUp style={{ width: '12px', height: '12px' }} />
                        <span>Like</span>
                      </button>
                      <button
                        onClick={() => handleFeedback(message.id, 1)}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '4px',
                          padding: '4px 8px',
                          borderRadius: '6px',
                          backgroundColor: '#374151',
                          border: 'none',
                          color: '#d1d5db',
                          fontSize: '12px',
                          cursor: 'pointer'
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.backgroundColor = 'rgba(239, 68, 68, 0.2)';
                          e.currentTarget.style.color = '#f87171';
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.backgroundColor = '#374151';
                          e.currentTarget.style.color = '#d1d5db';
                        }}
                        title="Bad response - help improve"
                      >
                        <ThumbsDown style={{ width: '12px', height: '12px' }} />
                        <span>Dislike</span>
                      </button>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        ))}
        {isLoading && (
          <div style={{ display: 'flex', gap: '12px' }}>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '50%',
              background: 'linear-gradient(135deg, #9333ea 0%, #2563eb 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <Bot style={{ width: '16px', height: '16px', color: 'white' }} />
            </div>
            <div style={{
              backgroundColor: '#1f2937',
              borderRadius: '16px',
              borderBottomLeftRadius: '4px',
              padding: '12px',
              border: '1px solid #374151'
            }}>
              <div style={{ display: 'flex', gap: '4px' }}>
                <div style={{
                  width: '8px',
                  height: '8px',
                  backgroundColor: '#9ca3af',
                  borderRadius: '50%',
                  animation: 'bounce 1s infinite'
                }} />
                <div style={{
                  width: '8px',
                  height: '8px',
                  backgroundColor: '#9ca3af',
                  borderRadius: '50%',
                  animation: 'bounce 1s infinite 0.1s'
                }} />
                <div style={{
                  width: '8px',
                  height: '8px',
                  backgroundColor: '#9ca3af',
                  borderRadius: '50%',
                  animation: 'bounce 1s infinite 0.2s'
                }} />
              </div>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div style={{
        padding: '16px',
        borderTop: '1px solid #374151',
        backgroundColor: '#111827',
        borderBottomLeftRadius: '16px',
        borderBottomRightRadius: '16px',
        flexShrink: 0
      }}>
        <div style={{ display: 'flex', gap: '8px' }}>
          <textarea
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Ask about logs, attacks, or security..."
            style={{
              flex: 1,
              backgroundColor: '#1f2937',
              border: '1px solid #374151',
              borderRadius: '12px',
              padding: '8px 16px',
              fontSize: '14px',
              color: 'white',
              resize: 'none',
              minHeight: '60px'
            }}
            rows={2}
            disabled={isLoading}
          />
          <button
            onClick={handleSend}
            disabled={!input.trim() || isLoading}
            style={{
              width: '40px',
              height: '40px',
              background: 'linear-gradient(135deg, #9333ea 0%, #2563eb 100%)',
              color: 'white',
              border: 'none',
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: !input.trim() || isLoading ? 'not-allowed' : 'pointer',
              opacity: !input.trim() || isLoading ? 0.5 : 1
            }}
          >
            <Send style={{ width: '16px', height: '16px' }} />
          </button>
        </div>
        <p style={{ fontSize: '12px', color: '#6b7280', marginTop: '8px' }}>
          Press Enter to send, Shift+Enter for new line
        </p>
      </div>
    </div>
  );
}
