// Agent Memory and Context Management
import type { AgentMessage, AgentConversation, DataRequest, DataResponse } from '../types';

// Simple UUID generation
function generateId(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

export class AgentMemory {
  private conversations: Map<string, AgentConversation> = new Map();
  private currentConversationId: string | null = null;

  // Create a new conversation
  createConversation(context?: Record<string, any>): AgentConversation {
    const id = generateId();
    const conversation: AgentConversation = {
      id,
      messages: [],
      startedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      context
    };
    
    this.conversations.set(id, conversation);
    this.currentConversationId = id;
    
    return conversation;
  }

  // Get current conversation
  getCurrentConversation(): AgentConversation | null {
    if (!this.currentConversationId) {
      return null;
    }
    return this.conversations.get(this.currentConversationId) || null;
  }

  // Switch to a conversation
  switchConversation(conversationId: string): boolean {
    if (this.conversations.has(conversationId)) {
      this.currentConversationId = conversationId;
      return true;
    }
    return false;
  }

  // Add message to current conversation
  addMessage(role: 'user' | 'agent' | 'system', content: string, dataRequests?: DataRequest[], dataResponses?: DataResponse[]): AgentMessage {
    const conversation = this.getCurrentConversation();
    if (!conversation) {
      throw new Error('No active conversation. Create one first.');
    }

    const message: AgentMessage = {
      id: generateId(),
      role,
      content,
      timestamp: new Date().toISOString(),
      dataRequests,
      dataResponses
    };

    conversation.messages.push(message);
    conversation.updatedAt = new Date().toISOString();

    return message;
  }

  // Get conversation history for LLM context
  getConversationHistory(limit: number = 10): AgentMessage[] {
    const conversation = this.getCurrentConversation();
    if (!conversation) {
      return [];
    }
    
    return conversation.messages.slice(-limit);
  }

  // Get context for LLM
  getContext(): Record<string, any> {
    const conversation = this.getCurrentConversation();
    return conversation?.context || {};
  }

  // Update context
  updateContext(updates: Record<string, any>): void {
    const conversation = this.getCurrentConversation();
    if (conversation) {
      conversation.context = { ...conversation.context, ...updates };
      conversation.updatedAt = new Date().toISOString();
    }
  }

  // Clear current conversation
  clearCurrentConversation(): void {
    if (this.currentConversationId) {
      this.conversations.delete(this.currentConversationId);
      this.currentConversationId = null;
    }
  }

  // Get all conversations
  getAllConversations(): AgentConversation[] {
    return Array.from(this.conversations.values());
  }

  // Delete a conversation
  deleteConversation(conversationId: string): boolean {
    return this.conversations.delete(conversationId);
  }

  // Format history for LLM prompt
  formatHistoryForPrompt(): string {
    const history = this.getConversationHistory();
    if (history.length === 0) {
      return '';
    }

    return history.map(msg => {
      const prefix = msg.role === 'user' ? 'User' : msg.role === 'agent' ? 'Agent' : 'System';
      return `${prefix}: ${msg.content}`;
    }).join('\n\n');
  }
}

// Singleton instance
export const agentMemory = new AgentMemory();
